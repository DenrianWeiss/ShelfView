PAGE = b'<script src="js/signin.js"></script><script src="js/Blowfish.js"></script><button ng-click="doValidate()"></button>'
SCRIPT = b'''function doLogin() {
var bf = new Blowfish("secret");
var encrypt_username = bf.encrypt($scope.username);
var encrypt_password = bf.encrypt($scope.password);
$.ajax({url: "/api/randomtag"});
$.ajax({url: "/api/session", data: {
username: bf.base64Encode(encrypt_username), password: bf.base64Encode(encrypt_password),
encrypt_flag: "2", login_tag: localStorage.getItem("login_tag")}});
}'''
SCRIPT_NEGOTIATED = SCRIPT.replace(
    b'username: bf.base64Encode(encrypt_username), password: bf.base64Encode(encrypt_password),\n'
    b'encrypt_flag: "2"',
    b'username: encrypt_username, password: encrypt_password, encrypt_flag: $scope.encrypt_ctrl'
) + b'''
$scope.encrypt_ctrl = data.encrypt_ctrl;
encrypt_username = encryStr($scope.username);
encrypt_password = encryStr($scope.password);
charCode=charCode^127;
parseInt(charCode).toString(16);
'''
VIEWER = b'''var K = {VIDEO_PACKET_SIZE:373,SSI_HASH_SIZE:129,CLIENT_USERNAME_LENGTH:129,
CLINET_OWN_IP_LENGTH:65,CLINET_OWN_MAC_LENGTH:49};
var routes = ["/api/kvm/token","/api/settings/media/adviser","/api/settings/media/instance","/cd-server"];
new WebSocket(this.bmc_ip+"/kvm");'''
