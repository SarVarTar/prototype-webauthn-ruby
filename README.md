# PrototypeWebauthn

This is a library for basic user registration and authentication using the new FIDO2 Web Authentication API.

## Installation

Download the source files to a location of your choice.

## Using Rails 6 or above

Add this line to your application's Gemfile:
```ruby
gem 'prototype_webauthn', path: 'path/to/folder'
```
And then execute:
    $ bundle

to make sure your webpacker instance can interpret .erb files execute:
    $ rails webpacker:install:erb

then add following lines to your ```application.js``` and rename it to ```application.js.erb```
```ruby
import "<%= File.join(Gem.loaded_specs['prototype_webauthn'].full_gem_path, 'vendor', 'assets', 'javascripts', 'webauthn_prototype.js') %>";
import "<%= File.join(Gem.loaded_specs['prototype_webauthn'].full_gem_path, 'vendor', 'assets', 'javascripts', 'cbor.js') %>";
```

## not using Rails
Make sure your system can interpret Ruby code.
Place the prototype_webauthn.rb, webauthn_prototype.js and cbor.js where your system can use them.
This depends on your Framework.

## check everything works
To check if everything is available type into the browser console
```javascript
webauthn_test()
```
You should receive ```'Webauthn Javascript available'``` as response.

From your back end call:
```ruby
PrototypeWebauthn::Test.test()
```
which should print ```'gem loaded. ruby available.'``` into your server console.

## Registering an authenticator

generate random base64 encoded strings to use as challenge and id using:
```ruby
PrototypeWebauthn::Helper.generate_challenge()
PrototypeWebauthn::Helper.generate_id()
```
store them with the users mail address in a temporary storage then call:
```ruby
PrototypeWebauthn::Creation.generate_js_call(user_email, your_site_name, your_domain_string, challenge, id, response_path)
```
This returns a javascript function call as string. Execute this on client site.
The Javascript library should send a POST request to the response_path containing the authenticators response data.
Then call:
```ruby
ProtottypeWebauthn::Creation.decode_response(webauthn_response, stored_challenge, request_origin, your_domain_string)
```
with ```webauthn_response``` being the POST parameter.

This will return a ruby hash of following structure:
```ruby
{
  valid: [true/false],
  credential_id: response[:credential_id],
  public_key: response[:public_key]
}
```
if valid is true all data is correct and the credential_id and public_key can be stored in your database.

## Authenticating an user

generate random base64 encoded string to use as challenge
```ruby
PrototypeWebauthn::Helper.generate_challenge()
```
Save challenge and user handle in temporary storage.
retrieve the credential_id from database and call:
```ruby
PrototypeWebauthn::Authentication.generate_js_call(challenge, credential_id, response_path)
```
to receive the javascript function call as a string.
Execute the javascript call on client side.
This will send a POST request to the response_path, where
```ruby
PrototypeWebauthn::Authentication.authenticate?(webauthn_response, stored_challenge], request_origin, public_key_from_db)
```
will return true if the signature and metadata are valid.
Sign in the user.

## Contributing

Bug reports and pull requests are welcome on GitHub at https://github.com/[USERNAME]/prototype_webauthn.

## License

The gem is available as open source under the terms of the [MIT License](https://opensource.org/licenses/MIT).
