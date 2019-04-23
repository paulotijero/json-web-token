## JSON Web Token

Init the API

```bash
$ rails new my-api --api
```

Create the user model

```bash
$ rails g model User name email password_digest
```

Run migrations

```bash
$ rails db:migrate
```

Add bcrypt to Gemfile and run `bundle install`

```Gemfile
gem 'bcrypt', '~> 3.1.7'
```

Add `has_secure_password` to the user model as following

```ruby
class User < ApplicationRecord
  has_secure_password
end
```

Add `jwt` to Gemfile and run `bundle install`

```Gemfile
gem 'jwt'
```

Create a file `lib/json_web_token.rb` with the following content

```ruby
class JSONWebToken
  class << self
    # Encode a payload a generate a JWT
    def encode(payload, exp = 24.hours.from_now)
      payload[:exp] = exp.to_i
      JWT.encode(payload, Rails.application.secrets.secret_key_base)
    end
    # Decode a JWT and get the payload
    def decode(token)
      body = JWT.decode(token, Rails.application.secrets.secret_key_base)[0]
      HashWithIndifferentAccess.new body
    rescue
      nil
    end
  end
end
```

Now let's ensure Rails load the content of the lib folder in `config/application.rb`

```ruby
module ApiApp
  class Application < Rails::Application
    #.....
    config.autoload_paths << Rails.root.join('lib')
    #.....
  end
end
```

Let's start the user login, we will create a file `app/controllers/authentication_controller.rb` with the content:

```ruby
class AuthenticationController < ApplicationController
  skip_before_action :authenticate_request

  def authenticate
    token = generate_token if user

    if token.nil?
      render json: { error: "Invalid credentials" }, status: :unauthorized
    else
      render json: { auth_token: token }
    end
  end

  private

  def generate_token
    JSONWebToken.encode(user_id: user.id) if user
  end

  def user
    user = User.find_by_email(params[:email])
    user if user && user.authenticate(params[:password])
  end
end
```

And let's configure the routes in `config/routes.rb`.

```ruby
  post 'authenticate', to: 'authentication#authenticate'
```

Now lets update `app/controllers/application_controller.rb` to authenticate request checking if the token is valid.

```ruby
class ApplicationController < ActionController::API
  before_action :authenticate_request
  attr_reader :current_user

  private

  def authenticate_request
    @current_user = user(request.headers)
    render json: { error: 'Not Authorized' }, status: 401 unless @current_user
  end

  def user
    User.find(decoded_auth_token[:user_id]) if decoded_auth_token
  end

  def decoded_auth_token
    @decoded_auth_token ||= JSONWebToken.decode(http_auth_header)
  end

  def http_auth_header
    if request.headers['Authorization'].present?
      return request.headers['Authorization'].split(' ').last
    end
  end
end
```
