require 'securerandom'
require 'digest'
require 'cose'

module PrototypeWebauthn

  #use to test correct functioning of Ruby Code
  class Test
    def self.test
      puts 'gem loaded. ruby available.'
    end
  end

  #validations needed to authenticate the requests posted by Javascript
  class Validations
    def self.challenge?(challenge_received, challenge_expected)
      return challenge_received.eql? challenge_expected
    end

    def self.origin?(origin_received, origin_expected)
      if(origin_received.nil?)
        raise 'no origin header received'
        return
      end
      return origin_received.eql? origin_expected
    end

    def self.type?(type_received, type_expected)
      return type_received.eql? type_expected
    end

    def self.rp_id?(rp_id_received, rp_id)
      rp_id_expected = Digest::SHA256.digest(rp_id)
      return rp_id_received.eql? rp_id_expected
    end
  end

  # optional to generate challenge and id
  class Helper
    def self.generate_challenge()
      challenge = SecureRandom.base64(26)
    end

    def self.generate_id()
      id = SecureRandom.base64(13)
    end
  end

  class Creation
    # generates Javascript function call to communicate with the Authenticator
    def self.generate_js_call(email, rp_name, rp_domain, challenge, id, response_path)
      email = email.downcase
      return "webauthn_create_credential(#{challenge.split("")}, '#{rp_name}', '#{rp_domain}', '#{id}', '#{email}', '#{email}', '#{response_path}');"
    end

    # decodes and checks the Authenticator response and returns the result as hash
    def self.decode_response(response_data, session_challenge, request_origin, rp_domain)
      puts 'STARTING REGISTRATION'
      response = Authentication.decode_response_data(response_data)
      if response[:status].eql?('success')
        puts 'VALIDATING METADATA'
        if(
          Validations.challenge?(response[:challenge], session_challenge) &&
          Validations.origin?(response[:origin], request_origin) &&
          Validations.type?(response[:type], 'webauthn.create') &&
          Validations.rp_id?(response[:rp_id_hash], rp_domain))
          puts 'VALID'
          valid = true
        else
          puts 'VALIDATIONS FAILD'
          valid = false
        end
      else
        puts 'status: ' + response[:status]
        puts response[:errorType].upcase + ': ' + response[:error]
      end
      result = {
        valid: valid,
        credential_id: response[:credential_id],
        public_key: response[:public_key]
      }
      return result
    end
  end

  class Authentication
    # generates Javascript function call to communicate with the Authenticator
    def self.generate_js_call(challenge, webauthn_id, response_path)
      credential_id = JSON.parse(webauthn_id).values
      return "webauthn_get_credential(#{challenge.split("")}, #{credential_id}, '#{response_path}')"
    end

    # decodes Authenticator response and performs necessary checks. Returns true or false.
    def self.authenticate?(response_data, session_challenge, request_origin, public_key)
      puts 'STARTING AUTHENTICATION'
      response = decode_response_data(response_data)
      if response[:status].eql?('success')
       puts 'VALIDATING METADATA'
        if(
          Validations.challenge?(response[:challenge], session_challenge) &&
          Validations.type?(response[:type], 'webauthn.get') &&
          Validations.origin?(response[:origin], request_origin))
          puts 'VALIDATIONS SUCCEEDED'
        else
          puts 'VALIDATIONS FAILED'
          return false
        end
      else
        puts 'status: ' + response[:status]
        puts response[:errorType].upcase + ': ' + response[:error]
        return false
      end
      puts 'CHECKING SIGNATURE'
      return signature_valid?(public_key, response[:signed_data], response[:signature])
    end

    # decodes the authenticator response and returns data in usable format
    def self.decode_response_data(response_data)
      data = JSON.parse(response_data)
      if data["status"].eql?('fail')
        response = {
          status: data["status"],
          error: data["error"],
          errorType: data["errorType"]
        }
        return response
      else
        client_data = JSON.parse(data["client_data"])
        client_data_hash = Digest::SHA256.digest(JSON.parse(data["client_data_bytes"]).values.map{|a| a.chr}.join)
        signature = ''
        rp_id_hash = ''
        auth_data = ''
        signed_data = ''
        if JSON.parse(data["auth_data"]).nil?
          rp_id_hash = JSON.parse(data["rp_id_hash"]).values.map{|a| a.chr}.join()
        else
          signature = JSON.parse(data["signature"]).values.map{|a| a.chr}.join()
          auth_data = JSON.parse(data["auth_data"])&.values&.map{|a| a.chr}&.join()
          signed_data = auth_data + client_data_hash
        end
        response = {
          origin: client_data["origin"],
          type: client_data["type"],
          challenge: Base64.urlsafe_decode64(client_data["challenge"]),
          status: data["status"],
          signed_data: signed_data,
          signature: signature,
          rp_id_hash: rp_id_hash,
          public_key: data["public_key"],
          credential_id: data["credential_id"],
        }
        return response
      end
    end

    # checks the signature for validity
    def self.signature_valid?(public_key, signed_data, signature)
      public_key_hex = JSON.parse(public_key).values.map{|a| a.chr}.join()
      public_key = COSE::Key.deserialize(public_key_hex)
      openssl_key = public_key.to_pkey
      result = openssl_key.verify(OpenSSL::Digest::SHA256.new, signature, signed_data)
      if(result)
        puts 'SIGNATURE VALID'
      else
        puts 'SIGNATURE INVALID'
      end
      return result
    end
  end

end
