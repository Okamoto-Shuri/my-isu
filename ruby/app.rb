require 'sinatra/base'
require 'mysql2'
require 'rack-flash'
require 'shellwords'
require 'rack/session/dalli'
require 'connection_pool'
require 'rack/deflater'

module Isuconp
  class App < Sinatra::Base
    use Rack::Deflater
    use Rack::Session::Dalli, autofix_keys: true, secret: ENV['ISUCONP_SESSION_SECRET'] || 'sendagaya', memcache_server: ENV['ISUCONP_MEMCACHED_ADDRESS'] || 'localhost:11211'
    use Rack::Flash
    set :public_folder, File.expand_path('../../public', __FILE__)

    # refs: https://github.com/advisories/GHSA-hxx2-7vcw-mqr3
    set :host_authorization, { permitted_hosts: [] }

    UPLOAD_LIMIT = 10 * 1024 * 1024 # 10mb

    POSTS_PER_PAGE = 20

    helpers do
      def config
        @config ||= {
          db: {
            host: ENV['ISUCONP_DB_HOST'] || 'localhost',
            port: ENV['ISUCONP_DB_PORT'] && ENV['ISUCONP_DB_PORT'].to_i,
            username: ENV['ISUCONP_DB_USER'] || 'root',
            password: ENV['ISUCONP_DB_PASSWORD'],
            database: ENV['ISUCONP_DB_NAME'] || 'isuconp',
          },
        }
      end

      def db
        return Thread.current[:isuconp_db] if Thread.current[:isuconp_db]
        client = Mysql2::Client.new(
          host: config[:db][:host],
          port: config[:db][:port],
          username: config[:db][:username],
          password: config[:db][:password],
          database: config[:db][:database],
          encoding: 'utf8mb4',
          reconnect: true,
          pool_size: 20,
          timeout: 5000,
        )
        client.query_options.merge!(symbolize_keys: true, database_timezone: :local, application_timezone: :local)
        Thread.current[:isuconp_db] = client
        client
      end

      def db_initialize
        sql = []
        sql << 'DELETE FROM users WHERE id > 1000'
        sql << 'DELETE FROM posts WHERE id > 10000'
        sql << 'DELETE FROM comments WHERE id > 100000'
        sql << 'UPDATE users SET del_flg = 0'
        sql << 'UPDATE users SET del_flg = 1 WHERE id % 50 = 0'
        sql.each do |s|
          db.prepare(s).execute
        end
      end

      def try_login(account_name, password)
        user = db.prepare('SELECT * FROM users WHERE account_name = ? AND del_flg = 0').execute(account_name).first

        if user && calculate_passhash(user[:account_name], password) == user[:passhash]
          return user
        else
          return nil
        end
      end

      def validate_user(account_name, password)
        if !(/\A[0-9a-zA-Z_]{3,}\z/.match(account_name) && /\A[0-9a-zA-Z_]{6,}\z/.match(password))
          return false
        end

        return true
      end

      def digest(src)
        # opensslのバージョンによっては (stdin)= というのがつくので取る
        `printf "%s" #{Shellwords.shellescape(src)} | openssl dgst -sha512 | sed 's/^.*= //'`.strip
      end

      def calculate_salt(account_name)
        digest account_name
      end

      def calculate_passhash(account_name, password)
        digest "#{password}:#{calculate_salt(account_name)}"
      end

      def get_session_user()
        if session[:user]
          # Cache user data in session to avoid repeated DB queries
          if session[:user_data]
            session[:user_data]
          else
            user_data = db.prepare('SELECT * FROM `users` WHERE `id` = ?').execute(
              session[:user][:id]
            ).first
            session[:user_data] = user_data
            user_data
          end
        else
          nil
        end
      end

      def make_posts(results, all_comments: false)
        posts = results.to_a
        return [] if posts.empty?
        
        post_ids = posts.map { |post| post[:id] }
        user_ids = posts.map { |post| post[:user_id] }
        
        # Batch load comment counts
        comment_counts = {}
        if post_ids.any?
          placeholder = (['?'] * post_ids.length).join(',')
          db.prepare("SELECT post_id, COUNT(*) AS count FROM comments WHERE post_id IN (#{placeholder}) GROUP BY post_id").execute(*post_ids).each do |row|
            comment_counts[row[:post_id]] = row[:count]
          end
        end
        
        # Batch load comments
        comments_by_post = {}
        if post_ids.any?
          placeholder = (['?'] * post_ids.length).join(',')
          limit_clause = all_comments ? '' : ' LIMIT 3'
          query = "SELECT * FROM comments WHERE post_id IN (#{placeholder}) ORDER BY created_at DESC#{limit_clause}"
          db.prepare(query).execute(*post_ids).each do |comment|
            comments_by_post[comment[:post_id]] ||= []
            comments_by_post[comment[:post_id]] << comment
          end
        end
        
        # Batch load comment users
        comment_user_ids = comments_by_post.values.flatten.map { |comment| comment[:user_id] }.uniq
        comment_users = {}
        if comment_user_ids.any?
          placeholder = (['?'] * comment_user_ids.length).join(',')
          db.prepare("SELECT * FROM users WHERE id IN (#{placeholder})").execute(*comment_user_ids).each do |user|
            comment_users[user[:id]] = user
          end
        end
        
        # Batch load post users
        post_users = {}
        if user_ids.any?
          placeholder = (['?'] * user_ids.length).join(',')
          db.prepare("SELECT * FROM users WHERE id IN (#{placeholder})").execute(*user_ids).each do |user|
            post_users[user[:id]] = user
          end
        end
        
        # Build final posts array
        final_posts = []
        posts.each do |post|
          post[:comment_count] = comment_counts[post[:id]] || 0
          
          comments = comments_by_post[post[:id]] || []
          comments.each do |comment|
            comment[:user] = comment_users[comment[:user_id]]
          end
          post[:comments] = comments.reverse
          
          post[:user] = post_users[post[:user_id]]
          
          if post[:user] && post[:user][:del_flg] == 0
            final_posts.push(post)
            break if final_posts.length >= POSTS_PER_PAGE
          end
        end
        
        final_posts
      end

      def image_url(post)
        ext = ""
        if post[:mime] == "image/jpeg"
          ext = ".jpg"
        elsif post[:mime] == "image/png"
          ext = ".png"
        elsif post[:mime] == "image/gif"
          ext = ".gif"
        end

        "/image/#{post[:id]}#{ext}"
      end
    end

    get '/initialize' do
      db_initialize
      
      # Add database indexes for performance
      db.query('CREATE INDEX IF NOT EXISTS idx_posts_created_at ON posts(created_at)')
      db.query('CREATE INDEX IF NOT EXISTS idx_posts_user_id ON posts(user_id)')
      db.query('CREATE INDEX IF NOT EXISTS idx_posts_user_created ON posts(user_id, created_at)')
      db.query('CREATE INDEX IF NOT EXISTS idx_comments_post_id ON comments(post_id)')
      db.query('CREATE INDEX IF NOT EXISTS idx_comments_user_id ON comments(user_id)')
      db.query('CREATE INDEX IF NOT EXISTS idx_comments_post_created ON comments(post_id, created_at)')
      db.query('CREATE INDEX IF NOT EXISTS idx_users_account_name ON users(account_name)')
      db.query('CREATE INDEX IF NOT EXISTS idx_users_del_flg ON users(del_flg)')
      db.query('CREATE INDEX IF NOT EXISTS idx_users_authority_del ON users(authority, del_flg)')
      
      return 200
    end

    get '/login' do
      if get_session_user()
        redirect '/', 302
      end
      erb :login, layout: :layout, locals: { me: nil }
    end

    post '/login' do
      if get_session_user()
        redirect '/', 302
      end

      user = try_login(params['account_name'], params['password'])
      if user
        session[:user] = {
          id: user[:id]
        }
        session[:csrf_token] = SecureRandom.hex(16)
        redirect '/', 302
      else
        flash[:notice] = 'アカウント名かパスワードが間違っています'
        redirect '/login', 302
      end
    end

    get '/register' do
      if get_session_user()
        redirect '/', 302
      end
      erb :register, layout: :layout, locals: { me: nil }
    end

    post '/register' do
      if get_session_user()
        redirect '/', 302
      end

      account_name = params['account_name']
      password = params['password']

      validated = validate_user(account_name, password)
      if !validated
        flash[:notice] = 'アカウント名は3文字以上、パスワードは6文字以上である必要があります'
        redirect '/register', 302
        return
      end

      user = db.prepare('SELECT 1 FROM users WHERE `account_name` = ?').execute(account_name).first
      if user
        flash[:notice] = 'アカウント名がすでに使われています'
        redirect '/register', 302
        return
      end

      query = 'INSERT INTO `users` (`account_name`, `passhash`) VALUES (?,?)'
      db.prepare(query).execute(
        account_name,
        calculate_passhash(account_name, password)
      )

      session[:user] = {
        id: db.last_id
      }
      session[:csrf_token] = SecureRandom.hex(16)
      redirect '/', 302
    end

    get '/logout' do
      session.delete(:user)
      session.delete(:user_data)
      redirect '/', 302
    end

    get '/' do
      me = get_session_user()

      results = db.query('SELECT `id`, `user_id`, `body`, `created_at`, `mime` FROM `posts` ORDER BY `created_at` DESC LIMIT 20')
      posts = make_posts(results)

      erb :index, layout: :layout, locals: { posts: posts, me: me }
    end

    get '/@:account_name' do
      user = db.prepare('SELECT * FROM `users` WHERE `account_name` = ? AND `del_flg` = 0').execute(
        params[:account_name]
      ).first

      if user.nil?
        return 404
      end

      results = db.prepare('SELECT `id`, `user_id`, `body`, `mime`, `created_at` FROM `posts` WHERE `user_id` = ? ORDER BY `created_at` DESC LIMIT 20').execute(
        user[:id]
      )
      posts = make_posts(results)

      # Optimize user statistics with single query
      stats = db.prepare('
        SELECT 
          (SELECT COUNT(*) FROM comments WHERE user_id = ?) as comment_count,
          (SELECT COUNT(*) FROM posts WHERE user_id = ?) as post_count,
          (SELECT COUNT(*) FROM comments c 
           INNER JOIN posts p ON c.post_id = p.id 
           WHERE p.user_id = ?) as commented_count
      ').execute(user[:id], user[:id], user[:id]).first
      
      comment_count = stats[:comment_count]
      post_count = stats[:post_count]
      commented_count = stats[:commented_count]

      me = get_session_user()

      erb :user, layout: :layout, locals: { posts: posts, user: user, post_count: post_count, comment_count: comment_count, commented_count: commented_count, me: me }
    end

    get '/posts' do
      max_created_at = params['max_created_at']
      results = db.prepare('SELECT `id`, `user_id`, `body`, `mime`, `created_at` FROM `posts` WHERE `created_at` <= ? ORDER BY `created_at` DESC LIMIT 20').execute(
        max_created_at.nil? ? nil : Time.iso8601(max_created_at).localtime
      )
      posts = make_posts(results)

      erb :posts, layout: false, locals: { posts: posts }
    end

    get '/posts/:id' do
      results = db.prepare('SELECT * FROM `posts` WHERE `id` = ?').execute(
        params[:id]
      )
      posts = make_posts(results, all_comments: true)

      return 404 if posts.length == 0

      post = posts[0]

      me = get_session_user()

      erb :post, layout: :layout, locals: { post: post, me: me }
    end

    post '/' do
      me = get_session_user()

      if me.nil?
        redirect '/login', 302
      end

      if params['csrf_token'] != session[:csrf_token]
        return 422
      end

      if params['file']
        mime = ''
        # 投稿のContent-Typeからファイルのタイプを決定する
        if params["file"][:type].include? "jpeg"
          mime = "image/jpeg"
        elsif params["file"][:type].include? "png"
          mime = "image/png"
        elsif params["file"][:type].include? "gif"
          mime = "image/gif"
        else
          flash[:notice] = '投稿できる画像形式はjpgとpngとgifだけです'
          redirect '/', 302
        end

        if params['file'][:tempfile].read.length > UPLOAD_LIMIT
          flash[:notice] = 'ファイルサイズが大きすぎます'
          redirect '/', 302
        end

        params['file'][:tempfile].rewind
        query = 'INSERT INTO `posts` (`user_id`, `mime`, `imgdata`, `body`) VALUES (?,?,?,?)'
        db.prepare(query).execute(
          me[:id],
          mime,
          params["file"][:tempfile].read,
          params["body"],
        )
        pid = db.last_id

        redirect "/posts/#{pid}", 302
      else
        flash[:notice] = '画像が必須です'
        redirect '/', 302
      end
    end

    get '/image/:id.:ext' do
      if params[:id].to_i == 0
        return ""
      end

      post = db.prepare('SELECT * FROM `posts` WHERE `id` = ?').execute(params[:id].to_i).first

      if (params[:ext] == "jpg" && post[:mime] == "image/jpeg") ||
          (params[:ext] == "png" && post[:mime] == "image/png") ||
          (params[:ext] == "gif" && post[:mime] == "image/gif")
        headers['Content-Type'] = post[:mime]
        headers['Cache-Control'] = 'public, max-age=3600'
        headers['ETag'] = "\"#{post[:id]}-#{post[:created_at].to_i}\""
        return post[:imgdata]
      end

      return 404
    end

    post '/comment' do
      me = get_session_user()

      if me.nil?
        redirect '/login', 302
      end

      if params["csrf_token"] != session[:csrf_token]
        return 422
      end

      unless /\A[0-9]+\z/.match(params['post_id'])
        return 'post_idは整数のみです'
      end
      post_id = params['post_id']

      query = 'INSERT INTO `comments` (`post_id`, `user_id`, `comment`) VALUES (?,?,?)'
      db.prepare(query).execute(
        post_id,
        me[:id],
        params['comment']
      )

      redirect "/posts/#{post_id}", 302
    end

    get '/admin/banned' do
      me = get_session_user()

      if me.nil?
        redirect '/login', 302
      end

      if me[:authority] == 0
        return 403
      end

      users = db.query('SELECT * FROM `users` WHERE `authority` = 0 AND `del_flg` = 0 ORDER BY `created_at` DESC LIMIT 100')

      erb :banned, layout: :layout, locals: { users: users, me: me }
    end

    post '/admin/banned' do
      me = get_session_user()

      if me.nil?
        redirect '/', 302
      end

      if me[:authority] == 0
        return 403
      end

      if params['csrf_token'] != session[:csrf_token]
        return 422
      end

      query = 'UPDATE `users` SET `del_flg` = ? WHERE `id` = ?'

      params['uid'].each do |id|
        db.prepare(query).execute(1, id.to_i)
      end

      redirect '/admin/banned', 302
    end
  end
end
