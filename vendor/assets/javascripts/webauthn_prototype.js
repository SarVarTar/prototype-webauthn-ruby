webauthn_test = function(){
  console.log('Webauthn Javascript available')
}

// lets the authenticator create a credential and sends it to server
webauthn_create_credential = function(challenge, rp_name, rp_id, user_id, user_name, user_email, response_path) {
  //options for creating credentials
  const publicKeyCredentialCreationOptions = {
    challenge: Uint8Array.from(challenge, c => c.charCodeAt(0)),
    pubKeyCredParams: [
      { type: 'public-key', alg: -7 },
      { type: 'public-key', alg: -37 }
    ],
    rp: {
      name: rp_name,
      id: rp_id
    },
    user: {
      id: Uint8Array.from(user_id, c => c.charCodeAt(0)),
      name: user_email,
      displayName: user_name,
    },
    timeout: 6000
  }
  //let the authenticator create a credential, decode the response and send the data to server
    navigator.credentials.create({ publicKey: publicKeyCredentialCreationOptions }).
      then(function(credential){
        webauthn_send_json(webauthn_decode_credential(credential), response_path);
    },
    function(reason){
      webauthn_error(reason, response_path)
    });
}

//lets the authenticator retrieve a credential and sends it to server
webauthn_get_credential = function(challenge, credential_id, response_path){
  //options for requesting credentials
  const publicKeyCredentialRequestOptions = {
    challenge: Uint8Array.from(challenge, c => c.charCodeAt(0)),
    allowCredentials: [{
      id: new Uint8Array(credential_id), //the on registration generated id of the credential
      type: 'public-key',
      transports: ['usb']
    }],
    timeout: 6000,
  }
  //let the authenticator retrieve the credential, decode the response and send the data to Server
  navigator.credentials.get({ publicKey: publicKeyCredentialRequestOptions}).
    then( function(credential){
      webauthn_send_json(webauthn_decode_credential(credential), response_path);
  },
  function(reason){
    webauthn_error(reason, response_path)
  });
}

//collects all necessary data of athenticators response
webauthn_decode_credential = function(credential){
  const utf8Decoder = new TextDecoder('utf-8');
  client_data = utf8Decoder.decode(credential.response.clientDataJSON); //contains challenge, origin and type
  var credential_id = JSON.stringify(new Uint8Array(credential.rawId)); //used to identify a credential at authentication process
  client_data_bytes = JSON.stringify(new Uint8Array(credential.response.clientDataJSON))

  auth_data = 'null';
  signature = 'null';
  rp_id_hash = 'null';
  public_key = 'null';

  //rp_id_hash and public_key are only available on registration
  if(credential.response.attestationObject){
    const decodedAttestationObj = decode(credential.response.attestationObject); //contains authData, format und attestation Statement if given
    const {authData} = decodedAttestationObj; //contains the publicKey and Meta-Data
    rp_id_hash = JSON.stringify(authData.slice(0,32)); //needed to verify the registration request

    //calculating the Idlength and extracting it
    const dataView = new DataView(new ArrayBuffer(2));
    var idLenBytes = authData.slice(53,55);
    idLenBytes.forEach((value, index) => dataView.setUint8(index,value));
    const credentialIdLength = dataView.getUint16();

    //extracting the publicKey
    const publicKeyBytes = authData.slice(55 + credentialIdLength);
    public_key = JSON.stringify(new Uint8Array(publicKeyBytes));
  }
  //authenticator data and signature are only available on authentication
  else{
    auth_data = JSON.stringify(new Uint8Array(credential.response.authenticatorData))
    signature = JSON.stringify(new Uint8Array(credential.response.signature))
  }
  //collecting the data
  var data = {
    client_data: client_data,
    client_data_bytes: client_data_bytes,
    credential_id: credential_id,
    status: 'success',
    auth_data: auth_data,
    signature: signature,
    rp_id_hash: rp_id_hash,
    public_key: public_key
  }
  return JSON.stringify(data);
}

// collects error messages and prints them in browser console as well as sends them to Server
webauthn_error = function(reason, response_path){
  console.log('FAILED TO CREATE CREDENTIALS');
  console.log(reason);
  var response = {
    status: 'fail',
    errorType: reason.name,
    error: reason.message
  };
  response = JSON.stringify(response)
  webauthn_send_json(response, response_path);
}

//generates a Form to post the authenticator response with
webauthn_send_json = function(data, path){
  var body = document.getElementsByTagName("body")[0];
  var input = document.createElement('input');
  input.type = 'text';
  input.style = 'display: none'
  input.name ='webauthn_response';
  input.value = data;

  var form = document.createElement('form');
  form.action = path;
  form.method = 'post';

  form.appendChild(input);
  body.appendChild(form);

  form.submit();
}
