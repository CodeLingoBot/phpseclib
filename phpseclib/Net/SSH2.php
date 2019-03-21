<?php

/**
 * Pure-PHP implementation of SSHv2.
 *
 * PHP version 5
 *
 * Here are some examples of how to use this library:
 * <code>
 * <?php
 *    include 'vendor/autoload.php';
 *
 *    $ssh = new \phpseclib\Net\SSH2('www.domain.tld');
 *    if (!$ssh->login('username', 'password')) {
 *        exit('Login Failed');
 *    }
 *
 *    echo $ssh->exec('pwd');
 *    echo $ssh->exec('ls -la');
 * ?>
 * </code>
 *
 * <code>
 * <?php
 *    include 'vendor/autoload.php';
 *
 *    $key = new \phpseclib\Crypt\RSA();
 *    //$key->setPassword('whatever');
 *    $key->load(file_get_contents('privatekey'));
 *
 *    $ssh = new \phpseclib\Net\SSH2('www.domain.tld');
 *    if (!$ssh->login('username', $key)) {
 *        exit('Login Failed');
 *    }
 *
 *    echo $ssh->read('username@username:~$');
 *    $ssh->write("ls -la\n");
 *    echo $ssh->read('username@username:~$');
 * ?>
 * </code>
 *
 * @category  Net
 * @package   SSH2
 * @author    Jim Wigginton <terrafrost@php.net>
 * @copyright 2007 Jim Wigginton
 * @license   http://www.opensource.org/licenses/mit-license.html  MIT License
 * @link      http://phpseclib.sourceforge.net
 */

namespace phpseclib\Net;

use ParagonIE\ConstantTime\Base64;
use phpseclib\Crypt\Blowfish;
use phpseclib\Crypt\Hash;
use phpseclib\Crypt\Random;
use phpseclib\Crypt\RC4;
use phpseclib\Crypt\Rijndael;
use phpseclib\Crypt\AES;
use phpseclib\Crypt\RSA;
use phpseclib\Crypt\TripleDES;
use phpseclib\Crypt\Twofish;
use phpseclib\Math\BigInteger; // Used to do Diffie-Hellman key exchange and DSA/RSA signature verification.
use phpseclib\System\SSH\Agent;
use phpseclib\System\SSH\Agent\Identity as AgentIdentity;
use phpseclib\Exception\NoSupportedAlgorithmsException;
use phpseclib\Common\Functions\Strings;
use phpseclib\Common\Functions\Objects;

/**
 * Pure-PHP implementation of SSHv2.
 *
 * @package SSH2
 * @author  Jim Wigginton <terrafrost@php.net>
 * @access  public
 */
class SSH2
{
    /**#@+
     * Execution Bitmap Masks
     *
     * @see \phpseclib\Net\SSH2::bitmap
     * @access private
     */
    const MASK_CONSTRUCTOR   = 0x00000001;
    const MASK_CONNECTED     = 0x00000002;
    const MASK_LOGIN_REQ     = 0x00000004;
    const MASK_LOGIN         = 0x00000008;
    const MASK_SHELL         = 0x00000010;
    const MASK_WINDOW_ADJUST = 0x00000020;
    /**#@-*/

    /**#@+
     * Channel constants
     *
     * RFC4254 refers not to client and server channels but rather to sender and recipient channels.  we don't refer
     * to them in that way because RFC4254 toggles the meaning. the client sends a SSH_MSG_CHANNEL_OPEN message with
     * a sender channel and the server sends a SSH_MSG_CHANNEL_OPEN_CONFIRMATION in response, with a sender and a
     * recipient channel.  at first glance, you might conclude that SSH_MSG_CHANNEL_OPEN_CONFIRMATION's sender channel
     * would be the same thing as SSH_MSG_CHANNEL_OPEN's sender channel, but it's not, per this snippet:
     *     The 'recipient channel' is the channel number given in the original
     *     open request, and 'sender channel' is the channel number allocated by
     *     the other side.
     *
     * @see \phpseclib\Net\SSH2::send_channel_packet()
     * @see \phpseclib\Net\SSH2::get_channel_packet()
     * @access private
    */
    const CHANNEL_EXEC          = 1; // PuTTy uses 0x100
    const CHANNEL_SHELL         = 2;
    const CHANNEL_SUBSYSTEM     = 3;
    const CHANNEL_AGENT_FORWARD = 4;
    const CHANNEL_KEEP_ALIVE    = 5;
    /**#@-*/

    /**#@+
     * @access public
     * @see \phpseclib\Net\SSH2::getLog()
    */
    /**
     * Returns the message numbers
     */
    const LOG_SIMPLE = 1;
    /**
     * Returns the message content
     */
    const LOG_COMPLEX = 2;
    /**
     * Outputs the content real-time
     */
    const LOG_REALTIME = 3;
    /**
     * Dumps the content real-time to a file
     */
    const LOG_REALTIME_FILE = 4;
    /**
     * Make sure that the log never gets larger than this
     */
    const LOG_MAX_SIZE = 1048576; // 1024 * 1024
    /**#@-*/

    /**#@+
     * @access public
     * @see \phpseclib\Net\SSH2::read()
    */
    /**
     * Returns when a string matching $expect exactly is found
     */
    const READ_SIMPLE = 1;
    /**
     * Returns when a string matching the regular expression $expect is found
     */
    const READ_REGEX = 2;
    /**
     * Returns when a string matching the regular expression $expect is found
     */
    const READ_NEXT = 3;
    /**#@-*/

    /**
     * The SSH identifier
     *
     * @var string
     * @access private
     */
    private $identifier;

    /**
     * The Socket Object
     *
     * @var object
     * @access private
     */
    private $fsock;

    /**
     * Execution Bitmap
     *
     * The bits that are set represent functions that have been called already.  This is used to determine
     * if a requisite function has been successfully executed.  If not, an error should be thrown.
     *
     * @var int
     * @access private
     */
    protected $bitmap = 0;

    /**
     * Error information
     *
     * @see self::getErrors()
     * @see self::getLastError()
     * @var array
     * @access private
     */
    private $errors = [];

    /**
     * Server Identifier
     *
     * @see self::getServerIdentification()
     * @var array|false
     * @access private
     */
    private $server_identifier = false;

    /**
     * Key Exchange Algorithms
     *
     * @see self::getKexAlgorithims()
     * @var array|false
     * @access private
     */
    private $kex_algorithms = false;

    /**
     * Minimum Diffie-Hellman Group Bit Size in RFC 4419 Key Exchange Methods
     *
     * @see self::_key_exchange()
     * @var int
     * @access private
     */
    private $kex_dh_group_size_min = 1536;

    /**
     * Preferred Diffie-Hellman Group Bit Size in RFC 4419 Key Exchange Methods
     *
     * @see self::_key_exchange()
     * @var int
     * @access private
     */
    private $kex_dh_group_size_preferred = 2048;

    /**
     * Maximum Diffie-Hellman Group Bit Size in RFC 4419 Key Exchange Methods
     *
     * @see self::_key_exchange()
     * @var int
     * @access private
     */
    private $kex_dh_group_size_max = 4096;

    /**
     * Server Host Key Algorithms
     *
     * @see self::getServerHostKeyAlgorithms()
     * @var array|false
     * @access private
     */
    private $server_host_key_algorithms = false;

    /**
     * Encryption Algorithms: Client to Server
     *
     * @see self::getEncryptionAlgorithmsClient2Server()
     * @var array|false
     * @access private
     */
    private $encryption_algorithms_client_to_server = false;

    /**
     * Encryption Algorithms: Server to Client
     *
     * @see self::getEncryptionAlgorithmsServer2Client()
     * @var array|false
     * @access private
     */
    private $encryption_algorithms_server_to_client = false;

    /**
     * MAC Algorithms: Client to Server
     *
     * @see self::getMACAlgorithmsClient2Server()
     * @var array|false
     * @access private
     */
    private $mac_algorithms_client_to_server = false;

    /**
     * MAC Algorithms: Server to Client
     *
     * @see self::getMACAlgorithmsServer2Client()
     * @var array|false
     * @access private
     */
    private $mac_algorithms_server_to_client = false;

    /**
     * Compression Algorithms: Client to Server
     *
     * @see self::getCompressionAlgorithmsClient2Server()
     * @var array|false
     * @access private
     */
    private $compression_algorithms_client_to_server = false;

    /**
     * Compression Algorithms: Server to Client
     *
     * @see self::getCompressionAlgorithmsServer2Client()
     * @var array|false
     * @access private
     */
    private $compression_algorithms_server_to_client = false;

    /**
     * Languages: Server to Client
     *
     * @see self::getLanguagesServer2Client()
     * @var array|false
     * @access private
     */
    private $languages_server_to_client = false;

    /**
     * Languages: Client to Server
     *
     * @see self::getLanguagesClient2Server()
     * @var array|false
     * @access private
     */
    private $languages_client_to_server = false;

    /**
     * Block Size for Server to Client Encryption
     *
     * "Note that the length of the concatenation of 'packet_length',
     *  'padding_length', 'payload', and 'random padding' MUST be a multiple
     *  of the cipher block size or 8, whichever is larger.  This constraint
     *  MUST be enforced, even when using stream ciphers."
     *
     *  -- http://tools.ietf.org/html/rfc4253#section-6
     *
     * @see self::__construct()
     * @see self::_send_binary_packet()
     * @var int
     * @access private
     */
    private $encrypt_block_size = 8;

    /**
     * Block Size for Client to Server Encryption
     *
     * @see self::__construct()
     * @see self::_get_binary_packet()
     * @var int
     * @access private
     */
    private $decrypt_block_size = 8;

    /**
     * Server to Client Encryption Object
     *
     * @see self::_get_binary_packet()
     * @var object
     * @access private
     */
    private $decrypt = false;

    /**
     * Client to Server Encryption Object
     *
     * @see self::_send_binary_packet()
     * @var object
     * @access private
     */
    private $encrypt = false;

    /**
     * Client to Server HMAC Object
     *
     * @see self::_send_binary_packet()
     * @var object
     * @access private
     */
    private $hmac_create = false;

    /**
     * Server to Client HMAC Object
     *
     * @see self::_get_binary_packet()
     * @var object
     * @access private
     */
    private $hmac_check = false;

    /**
     * Size of server to client HMAC
     *
     * We need to know how big the HMAC will be for the server to client direction so that we know how many bytes to read.
     * For the client to server side, the HMAC object will make the HMAC as long as it needs to be.  All we need to do is
     * append it.
     *
     * @see self::_get_binary_packet()
     * @var int
     * @access private
     */
    private $hmac_size = false;

    /**
     * Server Public Host Key
     *
     * @see self::getServerPublicHostKey()
     * @var string
     * @access private
     */
    private $server_public_host_key;

    /**
     * Session identifier
     *
     * "The exchange hash H from the first key exchange is additionally
     *  used as the session identifier, which is a unique identifier for
     *  this connection."
     *
     *  -- http://tools.ietf.org/html/rfc4253#section-7.2
     *
     * @see self::_key_exchange()
     * @var string
     * @access private
     */
    private $session_id = false;

    /**
     * Exchange hash
     *
     * The current exchange hash
     *
     * @see self::_key_exchange()
     * @var string
     * @access private
     */
    private $exchange_hash = false;

    /**
     * Message Numbers
     *
     * @see self::__construct()
     * @var array
     * @access private
     */
    private $message_numbers = [];

    /**
     * Disconnection Message 'reason codes' defined in RFC4253
     *
     * @see self::__construct()
     * @var array
     * @access private
     */
    private $disconnect_reasons = [];

    /**
     * SSH_MSG_CHANNEL_OPEN_FAILURE 'reason codes', defined in RFC4254
     *
     * @see self::__construct()
     * @var array
     * @access private
     */
    private $channel_open_failure_reasons = [];

    /**
     * Terminal Modes
     *
     * @link http://tools.ietf.org/html/rfc4254#section-8
     * @see self::__construct()
     * @var array
     * @access private
     */
    private $terminal_modes = [];

    /**
     * SSH_MSG_CHANNEL_EXTENDED_DATA's data_type_codes
     *
     * @link http://tools.ietf.org/html/rfc4254#section-5.2
     * @see self::__construct()
     * @var array
     * @access private
     */
    private $channel_extended_data_type_codes = [];

    /**
     * Send Sequence Number
     *
     * See 'Section 6.4.  Data Integrity' of rfc4253 for more info.
     *
     * @see self::_send_binary_packet()
     * @var int
     * @access private
     */
    private $send_seq_no = 0;

    /**
     * Get Sequence Number
     *
     * See 'Section 6.4.  Data Integrity' of rfc4253 for more info.
     *
     * @see self::_get_binary_packet()
     * @var int
     * @access private
     */
    private $get_seq_no = 0;

    /**
     * Server Channels
     *
     * Maps client channels to server channels
     *
     * @see self::get_channel_packet()
     * @see self::exec()
     * @var array
     * @access private
     */
    protected $server_channels = [];

    /**
     * Channel Buffers
     *
     * If a client requests a packet from one channel but receives two packets from another those packets should
     * be placed in a buffer
     *
     * @see self::get_channel_packet()
     * @see self::exec()
     * @var array
     * @access private
     */
    private $channel_buffers = [];

    /**
     * Channel Status
     *
     * Contains the type of the last sent message
     *
     * @see self::get_channel_packet()
     * @var array
     * @access private
     */
    protected $channel_status = [];

    /**
     * Packet Size
     *
     * Maximum packet size indexed by channel
     *
     * @see self::send_channel_packet()
     * @var array
     * @access private
     */
    private $packet_size_client_to_server = [];

    /**
     * Message Number Log
     *
     * @see self::getLog()
     * @var array
     * @access private
     */
    private $message_number_log = [];

    /**
     * Message Log
     *
     * @see self::getLog()
     * @var array
     * @access private
     */
    private $message_log = [];

    /**
     * The Window Size
     *
     * Bytes the other party can send before it must wait for the window to be adjusted (0x7FFFFFFF = 2GB)
     *
     * @var int
     * @see self::send_channel_packet()
     * @see self::exec()
     * @access private
     */
    protected $window_size = 0x7FFFFFFF;

    /**
     * Window size, server to client
     *
     * Window size indexed by channel
     *
     * @see self::send_channel_packet()
     * @var array
     * @access private
     */
    protected $window_size_server_to_client = [];

    /**
     * Window size, client to server
     *
     * Window size indexed by channel
     *
     * @see self::get_channel_packet()
     * @var array
     * @access private
     */
    private $window_size_client_to_server = [];

    /**
     * Server signature
     *
     * Verified against $this->session_id
     *
     * @see self::getServerPublicHostKey()
     * @var string
     * @access private
     */
    private $signature = '';

    /**
     * Server signature format
     *
     * ssh-rsa or ssh-dss.
     *
     * @see self::getServerPublicHostKey()
     * @var string
     * @access private
     */
    private $signature_format = '';

    /**
     * Interactive Buffer
     *
     * @see self::read()
     * @var array
     * @access private
     */
    private $interactiveBuffer = '';

    /**
     * Current log size
     *
     * Should never exceed self::LOG_MAX_SIZE
     *
     * @see self::_send_binary_packet()
     * @see self::_get_binary_packet()
     * @var int
     * @access private
     */
    private $log_size;

    /**
     * Timeout
     *
     * @see self::setTimeout()
     * @access private
     */
    private $timeout;

    /**
     * Current Timeout
     *
     * @see self::get_channel_packet()
     * @access private
     */
    protected $curTimeout;

    /**
     * Real-time log file pointer
     *
     * @see self::_append_log()
     * @var resource
     * @access private
     */
    private $realtime_log_file;

    /**
     * Real-time log file size
     *
     * @see self::_append_log()
     * @var int
     * @access private
     */
    private $realtime_log_size;

    /**
     * Has the signature been validated?
     *
     * @see self::getServerPublicHostKey()
     * @var bool
     * @access private
     */
    private $signature_validated = false;

    /**
     * Real-time log file wrap boolean
     *
     * @see self::_append_log()
     * @access private
     */
    private $realtime_log_wrap;

    /**
     * Flag to suppress stderr from output
     *
     * @see self::enableQuietMode()
     * @access private
     */
    private $quiet_mode = false;

    /**
     * Time of first network activity
     *
     * @var int
     * @access private
     */
    private $last_packet;

    /**
     * Exit status returned from ssh if any
     *
     * @var int
     * @access private
     */
    private $exit_status;

    /**
     * Flag to request a PTY when using exec()
     *
     * @var bool
     * @see self::enablePTY()
     * @access private
     */
    private $request_pty = false;

    /**
     * Flag set while exec() is running when using enablePTY()
     *
     * @var bool
     * @access private
     */
    private $in_request_pty_exec = false;

    /**
     * Flag set after startSubsystem() is called
     *
     * @var bool
     * @access private
     */
    private $in_subsystem;

    /**
     * Contents of stdError
     *
     * @var string
     * @access private
     */
    private $stdErrorLog;

    /**
     * The Last Interactive Response
     *
     * @see self::_keyboard_interactive_process()
     * @var string
     * @access private
     */
    private $last_interactive_response = '';

    /**
     * Keyboard Interactive Request / Responses
     *
     * @see self::_keyboard_interactive_process()
     * @var array
     * @access private
     */
    private $keyboard_requests_responses = [];

    /**
     * Banner Message
     *
     * Quoting from the RFC, "in some jurisdictions, sending a warning message before
     * authentication may be relevant for getting legal protection."
     *
     * @see self::_filter()
     * @see self::getBannerMessage()
     * @var string
     * @access private
     */
    private $banner_message = '';

    /**
     * Did read() timeout or return normally?
     *
     * @see self::isTimeout()
     * @var bool
     * @access private
     */
    private $is_timeout = false;

    /**
     * Log Boundary
     *
     * @see self::_format_log()
     * @var string
     * @access private
     */
    private $log_boundary = ':';

    /**
     * Log Long Width
     *
     * @see self::_format_log()
     * @var int
     * @access private
     */
    private $log_long_width = 65;

    /**
     * Log Short Width
     *
     * @see self::_format_log()
     * @var int
     * @access private
     */
    private $log_short_width = 16;

    /**
     * Hostname
     *
     * @see self::__construct()
     * @see self::_connect()
     * @var string
     * @access private
     */
    private $host;

    /**
     * Port Number
     *
     * @see self::__construct()
     * @see self::_connect()
     * @var int
     * @access private
     */
    private $port;

    /**
     * Number of columns for terminal window size
     *
     * @see self::getWindowColumns()
     * @see self::setWindowColumns()
     * @see self::setWindowSize()
     * @var int
     * @access private
     */
    private $windowColumns = 80;

    /**
     * Number of columns for terminal window size
     *
     * @see self::getWindowRows()
     * @see self::setWindowRows()
     * @see self::setWindowSize()
     * @var int
     * @access private
     */
    private $windowRows = 24;

    /**
     * Crypto Engine
     *
     * @see self::setCryptoEngine()
     * @see self::_key_exchange()
     * @var int
     * @access private
     */
    private $crypto_engine = false;

    /**
     * A System_SSH_Agent for use in the SSH2 Agent Forwarding scenario
     *
     * @var \phpseclib\System\Ssh\Agent
     * @access private
     */
    private $agent;

    /**
     * Connection storage to replicates ssh2 extension functionality:
     * {@link http://php.net/manual/en/wrappers.ssh2.php#refsect1-wrappers.ssh2-examples}
     *
     * @var SSH2[]
     */
    private static $connections;

    /**
     * Send the identification string first?
     *
     * @var bool
     * @access private
     */
    private $send_id_string_first = true;

    /**
     * Send the key exchange initiation packet first?
     *
     * @var bool
     * @access private
     */
    private $send_kex_first = true;

    /**
     * Some versions of OpenSSH incorrectly calculate the key size
     *
     * @var bool
     * @access private
     */
    private $bad_key_size_fix = false;

    /**
     * Should we try to re-connect to re-establish keys?
     *
     * @var bool
     * @access private
     */
    private $retry_connect = false;

    /**
     * Binary Packet Buffer
     *
     * @var string|false
     * @access private
     */
    private $binary_packet_buffer = false;

    /**
     * Preferred Signature Format
     *
     * @var string|false
     * @access private
     */
    var $preferred_signature_format = false;

    /**
     * Authentication Credentials
     *
     * @var array
     * @access private
     */
    var $auth = array();

    /**
     * Default Constructor.
     *
     * $host can either be a string, representing the host, or a stream resource.
     *
     * @param mixed $host
     * @param int $port
     * @param int $timeout
     * @see self::login()
     * @return SSH2|void
     * @access public
     */
    public function __construct($host, $port = 22, $timeout = 10)
    {
        $this->message_numbers = [
            1 => 'NET_SSH2_MSG_DISCONNECT',
            2 => 'NET_SSH2_MSG_IGNORE',
            3 => 'NET_SSH2_MSG_UNIMPLEMENTED',
            4 => 'NET_SSH2_MSG_DEBUG',
            5 => 'NET_SSH2_MSG_SERVICE_REQUEST',
            6 => 'NET_SSH2_MSG_SERVICE_ACCEPT',
            20 => 'NET_SSH2_MSG_KEXINIT',
            21 => 'NET_SSH2_MSG_NEWKEYS',
            30 => 'NET_SSH2_MSG_KEXDH_INIT',
            31 => 'NET_SSH2_MSG_KEXDH_REPLY',
            50 => 'NET_SSH2_MSG_USERAUTH_REQUEST',
            51 => 'NET_SSH2_MSG_USERAUTH_FAILURE',
            52 => 'NET_SSH2_MSG_USERAUTH_SUCCESS',
            53 => 'NET_SSH2_MSG_USERAUTH_BANNER',

            80 => 'NET_SSH2_MSG_GLOBAL_REQUEST',
            81 => 'NET_SSH2_MSG_REQUEST_SUCCESS',
            82 => 'NET_SSH2_MSG_REQUEST_FAILURE',
            90 => 'NET_SSH2_MSG_CHANNEL_OPEN',
            91 => 'NET_SSH2_MSG_CHANNEL_OPEN_CONFIRMATION',
            92 => 'NET_SSH2_MSG_CHANNEL_OPEN_FAILURE',
            93 => 'NET_SSH2_MSG_CHANNEL_WINDOW_ADJUST',
            94 => 'NET_SSH2_MSG_CHANNEL_DATA',
            95 => 'NET_SSH2_MSG_CHANNEL_EXTENDED_DATA',
            96 => 'NET_SSH2_MSG_CHANNEL_EOF',
            97 => 'NET_SSH2_MSG_CHANNEL_CLOSE',
            98 => 'NET_SSH2_MSG_CHANNEL_REQUEST',
            99 => 'NET_SSH2_MSG_CHANNEL_SUCCESS',
            100 => 'NET_SSH2_MSG_CHANNEL_FAILURE'
        ];
        $this->disconnect_reasons = [
            1 => 'NET_SSH2_DISCONNECT_HOST_NOT_ALLOWED_TO_CONNECT',
            2 => 'NET_SSH2_DISCONNECT_PROTOCOL_ERROR',
            3 => 'NET_SSH2_DISCONNECT_KEY_EXCHANGE_FAILED',
            4 => 'NET_SSH2_DISCONNECT_RESERVED',
            5 => 'NET_SSH2_DISCONNECT_MAC_ERROR',
            6 => 'NET_SSH2_DISCONNECT_COMPRESSION_ERROR',
            7 => 'NET_SSH2_DISCONNECT_SERVICE_NOT_AVAILABLE',
            8 => 'NET_SSH2_DISCONNECT_PROTOCOL_VERSION_NOT_SUPPORTED',
            9 => 'NET_SSH2_DISCONNECT_HOST_KEY_NOT_VERIFIABLE',
            10 => 'NET_SSH2_DISCONNECT_CONNECTION_LOST',
            11 => 'NET_SSH2_DISCONNECT_BY_APPLICATION',
            12 => 'NET_SSH2_DISCONNECT_TOO_MANY_CONNECTIONS',
            13 => 'NET_SSH2_DISCONNECT_AUTH_CANCELLED_BY_USER',
            14 => 'NET_SSH2_DISCONNECT_NO_MORE_AUTH_METHODS_AVAILABLE',
            15 => 'NET_SSH2_DISCONNECT_ILLEGAL_USER_NAME'
        ];
        $this->channel_open_failure_reasons = [
            1 => 'NET_SSH2_OPEN_ADMINISTRATIVELY_PROHIBITED'
        ];
        $this->terminal_modes = [
            0 => 'NET_SSH2_TTY_OP_END'
        ];
        $this->channel_extended_data_type_codes = [
            1 => 'NET_SSH2_EXTENDED_DATA_STDERR'
        ];

        $this->define_array(
            $this->message_numbers,
            $this->disconnect_reasons,
            $this->channel_open_failure_reasons,
            $this->terminal_modes,
            $this->channel_extended_data_type_codes,
            [60 => 'NET_SSH2_MSG_USERAUTH_PASSWD_CHANGEREQ'],
            [60 => 'NET_SSH2_MSG_USERAUTH_PK_OK'],
            [60 => 'NET_SSH2_MSG_USERAUTH_INFO_REQUEST',
                  61 => 'NET_SSH2_MSG_USERAUTH_INFO_RESPONSE'],
            // RFC 4419 - diffie-hellman-group-exchange-sha{1,256}
            [30 => 'NET_SSH2_MSG_KEXDH_GEX_REQUEST_OLD',
                  31 => 'NET_SSH2_MSG_KEXDH_GEX_GROUP',
                  32 => 'NET_SSH2_MSG_KEXDH_GEX_INIT',
                  33 => 'NET_SSH2_MSG_KEXDH_GEX_REPLY',
                  34 => 'NET_SSH2_MSG_KEXDH_GEX_REQUEST'],
            // RFC 5656 - Elliptic Curves (for curve25519-sha256@libssh.org)
            [30 => 'NET_SSH2_MSG_KEX_ECDH_INIT',
                  31 => 'NET_SSH2_MSG_KEX_ECDH_REPLY']
        );

        self::$connections[$this->getResourceId()] = $this;

        if (is_resource($host)) {
            $this->fsock = $host;
            return;
        }

        if (is_string($host)) {
            $this->host = $host;
            $this->port = $port;
            $this->timeout = $timeout;
        }
    }

    /**
     * Set Crypto Engine Mode
     *
     * Possible $engine values:
     * OpenSSL, mcrypt, Eval, PHP
     *
     * @param int $engine
     * @access public
     */
    public function setCryptoEngine($engine)
    {
        $this->crypto_engine = $engine;
    }

    /**
     * Send Identification String First
     *
     * https://tools.ietf.org/html/rfc4253#section-4.2 says "when the connection has been established,
     * both sides MUST send an identification string". It does not say which side sends it first. In
     * theory it shouldn't matter but it is a fact of life that some SSH servers are simply buggy
     *
     * @access public
     */
    public function sendIdentificationStringFirst()
    {
        $this->send_id_string_first = true;
    }

    /**
     * Send Identification String Last
     *
     * https://tools.ietf.org/html/rfc4253#section-4.2 says "when the connection has been established,
     * both sides MUST send an identification string". It does not say which side sends it first. In
     * theory it shouldn't matter but it is a fact of life that some SSH servers are simply buggy
     *
     * @access public
     */
    public function sendIdentificationStringLast()
    {
        $this->send_id_string_first = false;
    }

    /**
     * Send SSH_MSG_KEXINIT First
     *
     * https://tools.ietf.org/html/rfc4253#section-7.1 says "key exchange begins by each sending
     * sending the [SSH_MSG_KEXINIT] packet". It does not say which side sends it first. In theory
     * it shouldn't matter but it is a fact of life that some SSH servers are simply buggy
     *
     * @access public
     */
    public function sendKEXINITFirst()
    {
        $this->send_kex_first = true;
    }

    /**
     * Send SSH_MSG_KEXINIT Last
     *
     * https://tools.ietf.org/html/rfc4253#section-7.1 says "key exchange begins by each sending
     * sending the [SSH_MSG_KEXINIT] packet". It does not say which side sends it first. In theory
     * it shouldn't matter but it is a fact of life that some SSH servers are simply buggy
     *
     * @access public
     */
    public function sendKEXINITLast()
    {
        $this->send_kex_first = false;
    }

    /**
     * Connect to an SSHv2 server
     *
     * @return bool
     * @throws \UnexpectedValueException on receipt of unexpected packets
     * @throws \RuntimeException on other errors
     * @access private
     */
    

    /**
     * Generates the SSH identifier
     *
     * You should overwrite this method in your own class if you want to use another identifier
     *
     * @access protected
     * @return string
     */
    

    /**
     * Key Exchange
     * @return bool
     * @param string|bool $kexinit_payload_server optional
     * @throws \UnexpectedValueException on receipt of unexpected packets
     * @throws \RuntimeException on other errors
     * @throws \phpseclib\Exception\NoSupportedAlgorithmsException when none of the algorithms phpseclib has loaded are compatible
     * @access private
     */
    

    /**
     * Maps an encryption algorithm name to the number of key bytes.
     *
     * @param string $algorithm Name of the encryption algorithm
     * @return int|null Number of bytes as an integer or null for unknown
     * @access private
     */
    

    /**
     * Maps an encryption algorithm name to an instance of a subclass of
     * \phpseclib\Crypt\Base.
     *
     * @param string $algorithm Name of the encryption algorithm
     * @return mixed Instance of \phpseclib\Crypt\Base or null for unknown
     * @access private
     */
    

    /*
     * Tests whether or not proposed algorithm has a potential for issues
     *
     * @link https://www.chiark.greenend.org.uk/~sgtatham/putty/wishlist/ssh2-aesctr-openssh.html
     * @link https://bugzilla.mindrot.org/show_bug.cgi?id=1291
     * @param string $algorithm Name of the encryption algorithm
     * @return bool
     * @access private
     */
    private static function bad_algorithm_candidate($algorithm)
    {
        switch ($algorithm) {
            case 'arcfour256':
            case 'aes192-ctr':
            case 'aes256-ctr':
                return true;
        }

        return false;
    }

    /**
     * Login
     *
     * The $password parameter can be a plaintext password, a \phpseclib\Crypt\RSA object or an array
     *
     * @param string $username
     * @param $args[] param mixed $password
     * @return bool
     * @see self::_login()
     * @access public
     */
    public function login($username, ...$args)
    {
        $this->auth[] = array_merge([$username], $args);
        return $this->sublogin($username, ...$args);
    }

    /**
     * Login Helper
     *
     * @param string $username
     * @param $args[] param mixed $password
     * @return bool
     * @see self::_login_helper()
     * @access private
     */
    protected function sublogin($username, ...$args)
    {
        if (!($this->bitmap & self::MASK_CONSTRUCTOR)) {
            if (!$this->connect()) {
                return false;
            }
        }

        if (empty($args)) {
            return $this->login_helper($username);
        }

        foreach ($args as $arg) {
            if ($this->login_helper($username, $arg)) {
                return true;
            }
        }
        return false;
    }

    /**
     * Login Helper
     *
     * @param string $username
     * @param string $password
     * @return bool
     * @throws \UnexpectedValueException on receipt of unexpected packets
     * @throws \RuntimeException on other errors
     * @access private
     * @internal It might be worthwhile, at some point, to protect against {@link http://tools.ietf.org/html/rfc4251#section-9.3.9 traffic analysis}
     *           by sending dummy SSH_MSG_IGNORE messages.
     */
    

    /**
     * Login via keyboard-interactive authentication
     *
     * See {@link http://tools.ietf.org/html/rfc4256 RFC4256} for details.  This is not a full-featured keyboard-interactive authenticator.
     *
     * @param string $username
     * @param string $password
     * @return bool
     * @access private
     */
    

    /**
     * Handle the keyboard-interactive requests / responses.
     *
     * @param $responses[]
     * @return bool
     * @throws \RuntimeException on connection error
     * @access private
     */
    

    /**
     * Login with an ssh-agent provided key
     *
     * @param string $username
     * @param \phpseclib\System\SSH\Agent $agent
     * @return bool
     * @access private
     */
    

    /**
     * Login with an RSA private key
     *
     * @param string $username
     * @param \phpseclib\Crypt\RSA $password
     * @return bool
     * @throws \RuntimeException on connection error
     * @access private
     * @internal It might be worthwhile, at some point, to protect against {@link http://tools.ietf.org/html/rfc4251#section-9.3.9 traffic analysis}
     *           by sending dummy SSH_MSG_IGNORE messages.
     */
    

    /**
     * Set Timeout
     *
     * $ssh->exec('ping 127.0.0.1'); on a Linux host will never return and will run indefinitely.  setTimeout() makes it so it'll timeout.
     * Setting $timeout to false or 0 will mean there is no timeout.
     *
     * @param mixed $timeout
     * @access public
     */
    public function setTimeout($timeout)
    {
        $this->timeout = $this->curTimeout = $timeout;
    }

    /**
     * Get the output from stdError
     *
     * @access public
     */
    public function getStdError()
    {
        return $this->stdErrorLog;
    }

    /**
     * Execute Command
     *
     * If $callback is set to false then \phpseclib\Net\SSH2::get_channel_packet(self::CHANNEL_EXEC) will need to be called manually.
     * In all likelihood, this is not a feature you want to be taking advantage of.
     *
     * @param string $command
     * @param Callback $callback
     * @return string
     * @throws \RuntimeException on connection error
     * @access public
     */
    public function exec($command, $callback = null)
    {
        $this->curTimeout = $this->timeout;
        $this->is_timeout = false;
        $this->stdErrorLog = '';

        if (!$this->isAuthenticated()) {
            return false;
        }

        if ($this->in_request_pty_exec) {
            throw new \RuntimeException('If you want to run multiple exec()\'s you will need to disable (and re-enable if appropriate) a PTY for each one.');
        }

        // RFC4254 defines the (client) window size as "bytes the other party can send before it must wait for the window to
        // be adjusted".  0x7FFFFFFF is, at 2GB, the max size.  technically, it should probably be decremented, but,
        // honestly, if you're transferring more than 2GB, you probably shouldn't be using phpseclib, anyway.
        // see http://tools.ietf.org/html/rfc4254#section-5.2 for more info
        $this->window_size_server_to_client[self::CHANNEL_EXEC] = $this->window_size;
        // 0x8000 is the maximum max packet size, per http://tools.ietf.org/html/rfc4253#section-6.1, although since PuTTy
        // uses 0x4000, that's what will be used here, as well.
        $packet_size = 0x4000;

        $packet = pack(
            'CNa*N3',
            NET_SSH2_MSG_CHANNEL_OPEN,
            strlen('session'),
            'session',
            self::CHANNEL_EXEC,
            $this->window_size_server_to_client[self::CHANNEL_EXEC],
            $packet_size
        );

        if (!$this->send_binary_packet($packet)) {
            return false;
        }

        $this->channel_status[self::CHANNEL_EXEC] = NET_SSH2_MSG_CHANNEL_OPEN;

        $response = $this->get_channel_packet(self::CHANNEL_EXEC);
        if ($response === false) {
            return false;
        }

        if ($this->request_pty === true) {
            $terminal_modes = pack('C', NET_SSH2_TTY_OP_END);
            $packet = pack(
                'CNNa*CNa*N5a*',
                NET_SSH2_MSG_CHANNEL_REQUEST,
                $this->server_channels[self::CHANNEL_EXEC],
                strlen('pty-req'),
                'pty-req',
                1,
                strlen('vt100'),
                'vt100',
                $this->windowColumns,
                $this->windowRows,
                0,
                0,
                strlen($terminal_modes),
                $terminal_modes
            );

            if (!$this->send_binary_packet($packet)) {
                return false;
            }

            $response = $this->get_binary_packet();
            if ($response === false) {
                $this->bitmap = 0;
                throw new \RuntimeException('Connection closed by server');
            }

            if (!strlen($response)) {
                return false;
            }
            list(, $type) = unpack('C', Strings::shift($response, 1));

            switch ($type) {
                case NET_SSH2_MSG_CHANNEL_SUCCESS:
                    break;
                case NET_SSH2_MSG_CHANNEL_FAILURE:
                default:
                    $this->disconnect_helper(NET_SSH2_DISCONNECT_BY_APPLICATION);
                    throw new \RuntimeException('Unable to request pseudo-terminal');
            }
            $this->in_request_pty_exec = true;
        }

        // sending a pty-req SSH_MSG_CHANNEL_REQUEST message is unnecessary and, in fact, in most cases, slows things
        // down.  the one place where it might be desirable is if you're doing something like \phpseclib\Net\SSH2::exec('ping localhost &').
        // with a pty-req SSH_MSG_CHANNEL_REQUEST, exec() will return immediately and the ping process will then
        // then immediately terminate.  without such a request exec() will loop indefinitely.  the ping process won't end but
        // neither will your script.

        // although, in theory, the size of SSH_MSG_CHANNEL_REQUEST could exceed the maximum packet size established by
        // SSH_MSG_CHANNEL_OPEN_CONFIRMATION, RFC4254#section-5.1 states that the "maximum packet size" refers to the
        // "maximum size of an individual data packet". ie. SSH_MSG_CHANNEL_DATA.  RFC4254#section-5.2 corroborates.
        $packet = pack(
            'CNNa*CNa*',
            NET_SSH2_MSG_CHANNEL_REQUEST,
            $this->server_channels[self::CHANNEL_EXEC],
            strlen('exec'),
            'exec',
            1,
            strlen($command),
            $command
        );
        if (!$this->send_binary_packet($packet)) {
            return false;
        }

        $this->channel_status[self::CHANNEL_EXEC] = NET_SSH2_MSG_CHANNEL_REQUEST;

        $response = $this->get_channel_packet(self::CHANNEL_EXEC);
        if ($response === false) {
            return false;
        }

        $this->channel_status[self::CHANNEL_EXEC] = NET_SSH2_MSG_CHANNEL_DATA;

        if ($callback === false || $this->in_request_pty_exec) {
            return true;
        }

        $output = '';
        while (true) {
            $temp = $this->get_channel_packet(self::CHANNEL_EXEC);
            switch (true) {
                case $temp === true:
                    return is_callable($callback) ? true : $output;
                case $temp === false:
                    return false;
                default:
                    if (is_callable($callback)) {
                        if (call_user_func($callback, $temp) === true) {
                            $this->close_channel(self::CHANNEL_EXEC);
                            return true;
                        }
                    } else {
                        $output.= $temp;
                    }
            }
        }
    }

    /**
     * Creates an interactive shell
     *
     * @see self::read()
     * @see self::write()
     * @return bool
     * @throws \UnexpectedValueException on receipt of unexpected packets
     * @throws \RuntimeException on other errors
     * @access private
     */
    

    /**
     * Return the channel to be used with read() / write()
     *
     * @see self::read()
     * @see self::write()
     * @return int
     * @access public
     */
    

    /**
     * Return an available open channel
     *
     * @return int
     * @access public
     */
    

    /**
     * Returns the output of an interactive shell
     *
     * Returns when there's a match for $expect, which can take the form of a string literal or,
     * if $mode == self::READ_REGEX, a regular expression.
     *
     * @see self::write()
     * @param string $expect
     * @param int $mode
     * @return string|bool|null
     * @throws \RuntimeException on connection error
     * @access public
     */
    public function read($expect = '', $mode = self::READ_SIMPLE)
    {
        $this->curTimeout = $this->timeout;
        $this->is_timeout = false;

        if (!$this->isAuthenticated()) {
            throw new \RuntimeException('Operation disallowed prior to login()');
        }

        if (!($this->bitmap & self::MASK_SHELL) && !$this->initShell()) {
            throw new \RuntimeException('Unable to initiate an interactive shell session');
        }

        $channel = $this->get_interactive_channel();

        if ($mode == self::READ_NEXT) {
            return $this->get_channel_packet($channel);
        }

        $match = $expect;
        while (true) {
            if ($mode == self::READ_REGEX) {
                preg_match($expect, substr($this->interactiveBuffer, -1024), $matches);
                $match = isset($matches[0]) ? $matches[0] : '';
            }
            $pos = strlen($match) ? strpos($this->interactiveBuffer, $match) : false;
            if ($pos !== false) {
                return Strings::shift($this->interactiveBuffer, $pos + strlen($match));
            }
            $response = $this->get_channel_packet($channel);
            if (is_bool($response)) {
                $this->in_request_pty_exec = false;
                return $response ? Strings::shift($this->interactiveBuffer, strlen($this->interactiveBuffer)) : false;
            }

            $this->interactiveBuffer.= $response;
        }
    }

    /**
     * Inputs a command into an interactive shell.
     *
     * @see self::read()
     * @param string $cmd
     * @return bool
     * @throws \RuntimeException on connection error
     * @access public
     */
    public function write($cmd)
    {
        if (!$this->isAuthenticated()) {
            throw new \RuntimeException('Operation disallowed prior to login()');
        }

        if (!($this->bitmap & self::MASK_SHELL) && !$this->initShell()) {
            throw new \RuntimeException('Unable to initiate an interactive shell session');
        }

        return $this->send_channel_packet($this->get_interactive_channel(), $cmd);
    }

    /**
     * Start a subsystem.
     *
     * Right now only one subsystem at a time is supported. To support multiple subsystem's stopSubsystem() could accept
     * a string that contained the name of the subsystem, but at that point, only one subsystem of each type could be opened.
     * To support multiple subsystem's of the same name maybe it'd be best if startSubsystem() generated a new channel id and
     * returns that and then that that was passed into stopSubsystem() but that'll be saved for a future date and implemented
     * if there's sufficient demand for such a feature.
     *
     * @see self::stopSubsystem()
     * @param string $subsystem
     * @return bool
     * @access public
     */
    public function startSubsystem($subsystem)
    {
        $this->window_size_server_to_client[self::CHANNEL_SUBSYSTEM] = $this->window_size;

        $packet = pack(
            'CNa*N3',
            NET_SSH2_MSG_CHANNEL_OPEN,
            strlen('session'),
            'session',
            self::CHANNEL_SUBSYSTEM,
            $this->window_size,
            0x4000
        );

        if (!$this->send_binary_packet($packet)) {
            return false;
        }

        $this->channel_status[self::CHANNEL_SUBSYSTEM] = NET_SSH2_MSG_CHANNEL_OPEN;

        $response = $this->get_channel_packet(self::CHANNEL_SUBSYSTEM);
        if ($response === false) {
            return false;
        }

        $packet = pack(
            'CNNa*CNa*',
            NET_SSH2_MSG_CHANNEL_REQUEST,
            $this->server_channels[self::CHANNEL_SUBSYSTEM],
            strlen('subsystem'),
            'subsystem',
            1,
            strlen($subsystem),
            $subsystem
        );
        if (!$this->send_binary_packet($packet)) {
            return false;
        }

        $this->channel_status[self::CHANNEL_SUBSYSTEM] = NET_SSH2_MSG_CHANNEL_REQUEST;

        $response = $this->get_channel_packet(self::CHANNEL_SUBSYSTEM);

        if ($response === false) {
            return false;
        }

        $this->channel_status[self::CHANNEL_SUBSYSTEM] = NET_SSH2_MSG_CHANNEL_DATA;

        $this->bitmap |= self::MASK_SHELL;
        $this->in_subsystem = true;

        return true;
    }

    /**
     * Stops a subsystem.
     *
     * @see self::startSubsystem()
     * @return bool
     * @access public
     */
    public function stopSubsystem()
    {
        $this->in_subsystem = false;
        $this->close_channel(self::CHANNEL_SUBSYSTEM);
        return true;
    }

    /**
     * Closes a channel
     *
     * If read() timed out you might want to just close the channel and have it auto-restart on the next read() call
     *
     * @access public
     */
    public function reset()
    {
        $this->close_channel($this->get_interactive_channel());
    }

    /**
     * Is timeout?
     *
     * Did exec() or read() return because they timed out or because they encountered the end?
     *
     * @access public
     */
    public function isTimeout()
    {
        return $this->is_timeout;
    }

    /**
     * Disconnect
     *
     * @access public
     */
    public function disconnect()
    {
        $this->disconnect_helper(NET_SSH2_DISCONNECT_BY_APPLICATION);
        if (isset($this->realtime_log_file) && is_resource($this->realtime_log_file)) {
            fclose($this->realtime_log_file);
        }
        unset(self::$connections[$this->getResourceId()]);
    }

    /**
     * Destructor.
     *
     * Will be called, automatically, if you're supporting just PHP5.  If you're supporting PHP4, you'll need to call
     * disconnect().
     *
     * @access public
     */
    public function __destruct()
    {
        $this->disconnect();
    }

    /**
     * Is the connection still active?
     *
     * @return bool
     * @access public
     */
    public function isConnected()
    {
        return (bool) ($this->bitmap & self::MASK_CONNECTED);
    }

    /**
     * Have you successfully been logged in?
     *
     * @return bool
     * @access public
     */
    public function isAuthenticated()
    {
        return (bool) ($this->bitmap & self::MASK_LOGIN);
    }

    /**
     * Pings a server connection, or tries to reconnect if the connection has gone down
     *
     * Inspired by http://php.net/manual/en/mysqli.ping.php
     *
     * @return bool
     */
    public function ping()
    {
        if (!$this->isAuthenticated()) {
            return false;
        }

        $this->window_size_server_to_client[self::CHANNEL_KEEP_ALIVE] = $this->window_size;
        $packet_size = 0x4000;
        $packet = pack(
            'CNa*N3',
            NET_SSH2_MSG_CHANNEL_OPEN,
            strlen('session'),
            'session',
            self::CHANNEL_KEEP_ALIVE,
            $this->window_size_server_to_client[self::CHANNEL_KEEP_ALIVE],
            $packet_size
        );

        try {
            $this->send_binary_packet($packet);

            $this->channel_status[self::CHANNEL_KEEP_ALIVE] = NET_SSH2_MSG_CHANNEL_OPEN;

            $response = $this->get_channel_packet(self::CHANNEL_KEEP_ALIVE);
        } catch (\RuntimeException $e) {
            return $this->reconnect();
        }

        $this->close_channel(NET_SSH2_CHANNEL_KEEP_ALIVE);
        return true;
    }

    /**
     * In situ reconnect method
     *
     * @return boolean
     */
    

    /**
     * Resets a connection for re-use
     *
     * @param int $reason
     * @access private
     */
    

    /**
     * Gets Binary Packets
     *
     * See '6. Binary Packet Protocol' of rfc4253 for more info.
     *
     * @see self::_send_binary_packet()
     * @param bool $filter_channel_packets
     * @return string
     * @access private
     */
    

    /**
     * Read Remaining Bytes
     *
     * @see self::get_binary_packet()
     * @param int $remaining_length
     * @return string
     * @access private
     */
    

    /**
     * Filter Binary Packets
     *
     * Because some binary packets need to be ignored...
     *
     * @see self::_get_binary_packet()
     * @param string $payload
     * @param bool $filter_channel_packets
     * @return string
     * @access private
     */
    

    /**
     * Enable Quiet Mode
     *
     * Suppress stderr from output
     *
     * @access public
     */
    public function enableQuietMode()
    {
        $this->quiet_mode = true;
    }

    /**
     * Disable Quiet Mode
     *
     * Show stderr in output
     *
     * @access public
     */
    public function disableQuietMode()
    {
        $this->quiet_mode = false;
    }

    /**
     * Returns whether Quiet Mode is enabled or not
     *
     * @see self::enableQuietMode()
     * @see self::disableQuietMode()
     * @access public
     * @return bool
     */
    public function isQuietModeEnabled()
    {
        return $this->quiet_mode;
    }

    /**
     * Enable request-pty when using exec()
     *
     * @access public
     */
    public function enablePTY()
    {
        $this->request_pty = true;
    }

    /**
     * Disable request-pty when using exec()
     *
     * @access public
     */
    public function disablePTY()
    {
        if ($this->in_request_pty_exec) {
            $this->close_channel(self::CHANNEL_EXEC);
            $this->in_request_pty_exec = false;
        }
        $this->request_pty = false;
    }

    /**
     * Returns whether request-pty is enabled or not
     *
     * @see self::enablePTY()
     * @see self::disablePTY()
     * @access public
     * @return bool
     */
    public function isPTYEnabled()
    {
        return $this->request_pty;
    }

    /**
     * Gets channel data
     *
     * Returns the data as a string if it's available and false if not.
     *
     * @param int $client_channel
     * @param bool $skip_extended
     * @return mixed
     * @throws \RuntimeException on connection error
     * @access private
     */
    protected function get_channel_packet($client_channel, $skip_extended = false)
    {
        if (!empty($this->channel_buffers[$client_channel])) {
            return array_shift($this->channel_buffers[$client_channel]);
        }

        while (true) {
            if ($this->binary_packet_buffer !== false) {
                $response = $this->binary_packet_buffer;
                $this->binary_packet_buffer = false;
            } else {
                $read = array($this->fsock);
                $write = $except = null;

                if (!$this->curTimeout) {
                    @stream_select($read, $write, $except, null);
                } else {
                    if ($this->curTimeout < 0) {
                        $this->is_timeout = true;
                        return true;
                    }

                    $read = [$this->fsock];
                    $write = $except = null;

                    $start = microtime(true);
                    $sec = floor($this->curTimeout);
                    $usec = 1000000 * ($this->curTimeout - $sec);
                    // on windows this returns a "Warning: Invalid CRT parameters detected" error
                    if (!@stream_select($read, $write, $except, $sec, $usec) && !count($read)) {
                        $this->is_timeout = true;
                        return true;
                    }
                    $elapsed = microtime(true) - $start;
                    $this->curTimeout-= $elapsed;
                }

                $response = $this->get_binary_packet(true);
                if ($response === false) {
                    $this->bitmap = 0;
                    throw new \RuntimeException('Connection closed by server');
                }
            }

            if ($client_channel == -1 && $response === true) {
                return true;
            }
            if (!strlen($response)) {
                return false;
            }
            extract(unpack('Ctype', Strings::shift($response, 1)));
            /** @var integer $type */

            if (strlen($response) < 4) {
                return false;
            }
            if ($type == NET_SSH2_MSG_CHANNEL_OPEN) {
                extract(unpack('Nlength', Strings::shift($response, 4)));
                /** @var integer $length */
            } else {
                extract(unpack('Nchannel', Strings::shift($response, 4)));
                /** @var integer $channel */
            }

            // will not be setup yet on incoming channel open request
            if (isset($channel) && isset($this->channel_status[$channel]) && isset($this->window_size_server_to_client[$channel])) {
                $this->window_size_server_to_client[$channel]-= strlen($response);

                // resize the window, if appropriate
                if ($this->window_size_server_to_client[$channel] < 0) {
                    $packet = pack('CNN', NET_SSH2_MSG_CHANNEL_WINDOW_ADJUST, $this->server_channels[$channel], $this->window_size);
                    if (!$this->send_binary_packet($packet)) {
                        return false;
                    }
                    $this->window_size_server_to_client[$channel]+= $this->window_size;
                }

                switch ($type) {
                    case NET_SSH2_MSG_CHANNEL_EXTENDED_DATA:
                        /*
                        if ($client_channel == NET_SSH2_CHANNEL_EXEC) {
                            $this->send_channel_packet($client_channel, chr(0));
                        }
                        */
                        // currently, there's only one possible value for $data_type_code: NET_SSH2_EXTENDED_DATA_STDERR
                        if (strlen($response) < 8) {
                            return false;
                        }
                        extract(unpack('Ndata_type_code/Nlength', Strings::shift($response, 8)));
                        $data = Strings::shift($response, $length);
                        $this->stdErrorLog.= $data;
                        if ($skip_extended || $this->quiet_mode) {
                            continue 2;
                        }
                        if ($client_channel == $channel && $this->channel_status[$channel] == NET_SSH2_MSG_CHANNEL_DATA) {
                            return $data;
                        }
                        if (!isset($this->channel_buffers[$channel])) {
                            $this->channel_buffers[$channel] = array();
                        }
                        $this->channel_buffers[$channel][] = $data;

                        continue 2;
                    case NET_SSH2_MSG_CHANNEL_REQUEST:
                        if ($this->channel_status[$channel] == NET_SSH2_MSG_CHANNEL_CLOSE) {
                            continue 2;
                        }
                        if (strlen($response) < 4) {
                            return false;
                        }
                        extract(unpack('Nlength', Strings::shift($response, 4)));
                        $value = Strings::shift($response, $length);
                        switch ($value) {
                            case 'exit-signal':
                                Strings::shift($response, 1);
                                if (strlen($response) < 4) {
                                    return false;
                                }
                                extract(unpack('Nlength', Strings::shift($response, 4)));
                                /** @var integer $length */

                                $this->errors[] = 'SSH_MSG_CHANNEL_REQUEST (exit-signal): ' . Strings::shift($response, $length);
                                $this->_string_shift($response, 1);
                                if (strlen($response) < 4) {
                                    return false;
                                }
                                extract(unpack('Nlength', Strings::shift($response, 4)));
                                /** @var integer $length */

                                if ($length) {
                                    $this->errors[count($this->errors)].= "\r\n" . Strings::shift($response, $length);
                                }

                                $this->send_binary_packet(pack('CN', NET_SSH2_MSG_CHANNEL_EOF, $this->server_channels[$client_channel]));
                                $this->send_binary_packet(pack('CN', NET_SSH2_MSG_CHANNEL_CLOSE, $this->server_channels[$channel]));

                                $this->channel_status[$channel] = NET_SSH2_MSG_CHANNEL_EOF;

                                continue 3;
                            case 'exit-status':
                                if (strlen($response) < 5) {
                                    return false;
                                }
                                extract(unpack('Cfalse/Nexit_status', Strings::shift($response, 5)));
                                /**
                                 * @var integer $false
                                 * @var integer $exit_status
                                 */

                                $this->exit_status = $exit_status;

                                // "The client MAY ignore these messages."
                                // -- http://tools.ietf.org/html/rfc4254#section-6.10

                                continue 3;
                            default:
                                // "Some systems may not implement signals, in which case they SHOULD ignore this message."
                                //  -- http://tools.ietf.org/html/rfc4254#section-6.9
                                continue 3;
                        }
                }

                switch ($this->channel_status[$channel]) {
                    case NET_SSH2_MSG_CHANNEL_OPEN:
                        switch ($type) {
                            case NET_SSH2_MSG_CHANNEL_OPEN_CONFIRMATION:
                                if (strlen($response) < 4) {
                                    return false;
                                }
                                extract(unpack('Nserver_channel', Strings::shift($response, 4)));
                                /** @var integer $server_channel */
                                $this->server_channels[$channel] = $server_channel;
                                if (strlen($response) < 4) {
                                    return false;
                                }
                                extract(unpack('Nwindow_size', Strings::shift($response, 4)));
                                /** @var integer $window_size */

                                if ($window_size < 0) {
                                    $window_size&= 0x7FFFFFFF;
                                    $window_size+= 0x80000000;
                                }
                                $this->window_size_client_to_server[$channel] = $window_size;
                                if (strlen($response) < 4) {
                                     return false;
                                }
                                $temp = unpack('Npacket_size_client_to_server', Strings::shift($response, 4));

                                $this->packet_size_client_to_server[$channel] = $temp['packet_size_client_to_server'];
                                $result = $client_channel == $channel ? true : $this->get_channel_packet($client_channel, $skip_extended);
                                $this->on_channel_open();
                                return $result;
                            //case NET_SSH2_MSG_CHANNEL_OPEN_FAILURE:
                            default:
                                $this->disconnect_helper(NET_SSH2_DISCONNECT_BY_APPLICATION);
                                throw new \RuntimeException('Unable to open channel');
                        }
                        break;
                    case NET_SSH2_MSG_CHANNEL_REQUEST:
                        switch ($type) {
                            case NET_SSH2_MSG_CHANNEL_SUCCESS:
                                return true;
                            case NET_SSH2_MSG_CHANNEL_FAILURE:
                                return false;
                            default:
                                $this->disconnect_helper(NET_SSH2_DISCONNECT_BY_APPLICATION);
                                throw new \RuntimeException('Unable to fulfill channel request');
                        }
                    case NET_SSH2_MSG_CHANNEL_CLOSE:
                        return $type == NET_SSH2_MSG_CHANNEL_CLOSE ? true : $this->get_channel_packet($client_channel, $skip_extended);
                }
            }

            // ie. $this->channel_status[$channel] == NET_SSH2_MSG_CHANNEL_DATA

            switch ($type) {
                case NET_SSH2_MSG_CHANNEL_DATA:
                    /*
                    if ($channel == self::CHANNEL_EXEC) {
                        // SCP requires null packets, such as this, be sent.  further, in the case of the ssh.com SSH server
                        // this actually seems to make things twice as fast.  more to the point, the message right after
                        // SSH_MSG_CHANNEL_DATA (usually SSH_MSG_IGNORE) won't block for as long as it would have otherwise.
                        // in OpenSSH it slows things down but only by a couple thousandths of a second.
                        $this->send_channel_packet($channel, chr(0));
                    }
                    */
                    if (strlen($response) < 4) {
                        return false;
                    }
                    extract(unpack('Nlength', Strings::shift($response, 4)));
                    /** @var integer $length */

                    $data = Strings::shift($response, $length);

                    if ($channel == self::CHANNEL_AGENT_FORWARD) {
                        $agent_response = Objects::callFunc($this->agent, 'forward_data', [$data]);
                        if (!is_bool($agent_response)) {
                            $this->send_channel_packet($channel, $agent_response);
                        }
                        break;
                    }

                    if ($client_channel == $channel) {
                        return $data;
                    }
                    if (!isset($this->channel_buffers[$channel])) {
                        $this->channel_buffers[$channel] = [];
                    }
                    $this->channel_buffers[$channel][] = $data;
                    break;
                case NET_SSH2_MSG_CHANNEL_CLOSE:
                    $this->curTimeout = 0;

                    if ($this->bitmap & self::MASK_SHELL) {
                        $this->bitmap&= ~self::MASK_SHELL;
                    }
                    if ($this->channel_status[$channel] != NET_SSH2_MSG_CHANNEL_EOF) {
                        $this->send_binary_packet(pack('CN', NET_SSH2_MSG_CHANNEL_CLOSE, $this->server_channels[$channel]));
                    }

                    $this->channel_status[$channel] = NET_SSH2_MSG_CHANNEL_CLOSE;
                    if ($client_channel == $channel) {
                        return true;
                    }
                case NET_SSH2_MSG_CHANNEL_EOF:
                    break;
                default:
                    $this->disconnect_helper(NET_SSH2_DISCONNECT_BY_APPLICATION);
                    throw new \RuntimeException('Error reading channel data');
            }
        }
    }

    /**
     * Sends Binary Packets
     *
     * See '6. Binary Packet Protocol' of rfc4253 for more info.
     *
     * @param string $data
     * @param string $logged
     * @see self::_get_binary_packet()
     * @return bool
     * @access private
     */
    protected function send_binary_packet($data, $logged = null)
    {
        if (!is_resource($this->fsock) || feof($this->fsock)) {
            $this->bitmap = 0;
            throw new \RuntimeException('Connection closed prematurely');
        }

        //if ($this->compress) {
        //    // the -4 removes the checksum:
        //    // http://php.net/function.gzcompress#57710
        //    $data = substr(gzcompress($data), 0, -4);
        //}

        // 4 (packet length) + 1 (padding length) + 4 (minimal padding amount) == 9
        $packet_length = strlen($data) + 9;
        if ($this->encrypt && $this->encrypt->usesNonce()) {
            $packet_length-= 4;
        }
        // round up to the nearest $this->encrypt_block_size
        $packet_length+= (($this->encrypt_block_size - 1) * $packet_length) % $this->encrypt_block_size;
        // subtracting strlen($data) is obvious - subtracting 5 is necessary because of packet_length and padding_length
        $padding_length = $packet_length - strlen($data) - 5;
        if ($this->encrypt && $this->encrypt->usesNonce()) {
            $padding_length+= 4;
            $packet_length+= 4;
        }
        $padding = Random::string($padding_length);

        // we subtract 4 from packet_length because the packet_length field isn't supposed to include itself
        $packet = pack('NCa*', $packet_length - 4, $padding_length, $data . $padding);

        $hmac = $this->hmac_create ? $this->hmac_create->hash(pack('Na*', $this->send_seq_no, $packet)) : '';
        $this->send_seq_no++;

        if ($this->encrypt) {
            if (!$this->encrypt->usesNonce()) {
                $packet = $this->encrypt->encrypt($packet);
            } else {
                $this->encrypt->setNonce(
                    $this->encrypt->fixed .
                    $this->encrypt->invocation_counter
                );
                Strings::increment_str($this->encrypt->invocation_counter);
                $this->encrypt->setAAD($temp = substr($packet, 0, 4));
                $packet = $temp . $this->encrypt->encrypt(substr($packet, 4));
            }
        }

        $packet.= $this->encrypt && $this->encrypt->usesNonce() ? $this->encrypt->getTag() : $hmac;

        $start = microtime(true);
        $result = strlen($packet) == fputs($this->fsock, $packet);
        $stop = microtime(true);

        if (defined('NET_SSH2_LOGGING')) {
            $current = microtime(true);
            $message_number = isset($this->message_numbers[ord($data[0])]) ? $this->message_numbers[ord($data[0])] : 'UNKNOWN (' . ord($data[0]) . ')';
            $message_number = '-> ' . $message_number .
                              ' (since last: ' . round($current - $this->last_packet, 4) . ', network: ' . round($stop - $start, 4) . 's)';
            $this->append_log($message_number, isset($logged) ? $logged : $data);
            $this->last_packet = $current;
        }

        return $result;
    }

    /**
     * Logs data packets
     *
     * Makes sure that only the last 1MB worth of packets will be logged
     *
     * @param string $message_number
     * @param string $message
     * @access private
     */
    

    /**
     * Sends channel data
     *
     * Spans multiple SSH_MSG_CHANNEL_DATAs if appropriate
     *
     * @param int $client_channel
     * @param string $data
     * @return bool
     * @access private
     */
    protected function send_channel_packet($client_channel, $data)
    {
        while (strlen($data)) {
            if (!$this->window_size_client_to_server[$client_channel]) {
                $this->bitmap^= self::MASK_WINDOW_ADJUST;
                // using an invalid channel will let the buffers be built up for the valid channels
                $this->get_channel_packet(-1);
                $this->bitmap^= self::MASK_WINDOW_ADJUST;
            }

            /* The maximum amount of data allowed is determined by the maximum
               packet size for the channel, and the current window size, whichever
               is smaller.
                 -- http://tools.ietf.org/html/rfc4254#section-5.2 */
            $max_size = min(
                $this->packet_size_client_to_server[$client_channel],
                $this->window_size_client_to_server[$client_channel]
            );

            $temp = Strings::shift($data, $max_size);
            $packet = pack(
                'CN2a*',
                NET_SSH2_MSG_CHANNEL_DATA,
                $this->server_channels[$client_channel],
                strlen($temp),
                $temp
            );
            $this->window_size_client_to_server[$client_channel]-= strlen($temp);
            if (!$this->send_binary_packet($packet)) {
                return false;
            }
        }

        return true;
    }

    /**
     * Closes and flushes a channel
     *
     * \phpseclib\Net\SSH2 doesn't properly close most channels.  For exec() channels are normally closed by the server
     * and for SFTP channels are presumably closed when the client disconnects.  This functions is intended
     * for SCP more than anything.
     *
     * @param int $client_channel
     * @param bool $want_reply
     * @return bool
     * @access private
     */
    

    /**
     * Disconnect
     *
     * @param int $reason
     * @return bool
     * @access protected
     */
    protected function disconnect_helper($reason)
    {
        if ($this->bitmap & self::MASK_CONNECTED) {
            $data = pack('CNNa*Na*', NET_SSH2_MSG_DISCONNECT, $reason, 0, '', 0, '');
            $this->send_binary_packet($data);
            $this->bitmap = 0;
            fclose($this->fsock);
            return false;
        }
    }

    /**
     * Define Array
     *
     * Takes any number of arrays whose indices are integers and whose values are strings and defines a bunch of
     * named constants from it, using the value as the name of the constant and the index as the value of the constant.
     * If any of the constants that would be defined already exists, none of the constants will be defined.
     *
     * @param $args[]
     * @access protected
     */
    protected function define_array(...$args)
    {
        foreach ($args as $arg) {
            foreach ($arg as $key => $value) {
                if (!defined($value)) {
                    define($value, $key);
                } else {
                    break 2;
                }
            }
        }
    }

    /**
     * Returns a log of the packets that have been sent and received.
     *
     * Returns a string if NET_SSH2_LOGGING == self::LOG_COMPLEX, an array if NET_SSH2_LOGGING == self::LOG_SIMPLE and false if !defined('NET_SSH2_LOGGING')
     *
     * @access public
     * @return array|false|string
     */
    public function getLog()
    {
        if (!defined('NET_SSH2_LOGGING')) {
            return false;
        }

        switch (NET_SSH2_LOGGING) {
            case self::LOG_SIMPLE:
                return $this->message_number_log;
            case self::LOG_COMPLEX:
                $log = $this->format_log($this->message_log, $this->message_number_log);
                return PHP_SAPI == 'cli' ? $log : '<pre>' . $log . '</pre>';
            default:
                return false;
        }
    }

    /**
     * Formats a log for printing
     *
     * @param array $message_log
     * @param array $message_number_log
     * @access private
     * @return string
     */
    protected function format_log($message_log, $message_number_log)
    {
        $output = '';
        for ($i = 0; $i < count($message_log); $i++) {
            $output.= $message_number_log[$i] . "\r\n";
            $current_log = $message_log[$i];
            $j = 0;
            do {
                if (strlen($current_log)) {
                    $output.= str_pad(dechex($j), 7, '0', STR_PAD_LEFT) . '0  ';
                }
                $fragment = Strings::shift($current_log, $this->log_short_width);
                $hex = substr(preg_replace_callback('#.#s', [$this, 'format_log_helper'], $fragment), strlen($this->log_boundary));
                // replace non ASCII printable characters with dots
                // http://en.wikipedia.org/wiki/ASCII#ASCII_printable_characters
                // also replace < with a . since < messes up the output on web browsers
                $raw = preg_replace('#[^\x20-\x7E]|<#', '.', $fragment);
                $output.= str_pad($hex, $this->log_long_width - $this->log_short_width, ' ') . $raw . "\r\n";
                $j++;
            } while (strlen($current_log));
            $output.= "\r\n";
        }

        return $output;
    }

    /**
     * Helper function for _format_log
     *
     * For use with preg_replace_callback()
     *
     * @param array $matches
     * @access private
     * @return string
     */
    

    /**
     * Helper function for agent->on_channel_open()
     *
     * Used when channels are created to inform agent
     * of said channel opening. Must be called after
     * channel open confirmation received
     *
     * @access private
     */
    

    /**
     * Returns the first value of the intersection of two arrays or false if
     * the intersection is empty. The order is defined by the first parameter.
     *
     * @param array $array1
     * @param array $array2
     * @return mixed False if intersection is empty, else intersected value.
     * @access private
     */
    

    /**
     * Returns all errors
     *
     * @return string[]
     * @access public
     */
    public function getErrors()
    {
        return $this->errors;
    }

    /**
     * Returns the last error
     *
     * @return string
     * @access public
     */
    public function getLastError()
    {
        $count = count($this->errors);

        if ($count > 0) {
            return $this->errors[$count - 1];
        }
    }

    /**
     * Return the server identification.
     *
     * @return string
     * @access public
     */
    public function getServerIdentification()
    {
        $this->connect();

        return $this->server_identifier;
    }

    /**
     * Return a list of the key exchange algorithms the server supports.
     *
     * @return array
     * @access public
     */
    public function getKexAlgorithms()
    {
        $this->connect();

        return $this->kex_algorithms;
    }

    /**
     * Return a list of the host key (public key) algorithms the server supports.
     *
     * @return array
     * @access public
     */
    public function getServerHostKeyAlgorithms()
    {
        $this->connect();

        return $this->server_host_key_algorithms;
    }

    /**
     * Return a list of the (symmetric key) encryption algorithms the server supports, when receiving stuff from the client.
     *
     * @return array
     * @access public
     */
    public function getEncryptionAlgorithmsClient2Server()
    {
        $this->connect();

        return $this->encryption_algorithms_client_to_server;
    }

    /**
     * Return a list of the (symmetric key) encryption algorithms the server supports, when sending stuff to the client.
     *
     * @return array
     * @access public
     */
    public function getEncryptionAlgorithmsServer2Client()
    {
        $this->connect();

        return $this->encryption_algorithms_server_to_client;
    }

    /**
     * Return a list of the MAC algorithms the server supports, when receiving stuff from the client.
     *
     * @return array
     * @access public
     */
    public function getMACAlgorithmsClient2Server()
    {
        $this->connect();

        return $this->mac_algorithms_client_to_server;
    }

    /**
     * Return a list of the MAC algorithms the server supports, when sending stuff to the client.
     *
     * @return array
     * @access public
     */
    public function getMACAlgorithmsServer2Client()
    {
        $this->connect();

        return $this->mac_algorithms_server_to_client;
    }

    /**
     * Return a list of the compression algorithms the server supports, when receiving stuff from the client.
     *
     * @return array
     * @access public
     */
    public function getCompressionAlgorithmsClient2Server()
    {
        $this->connect();

        return $this->compression_algorithms_client_to_server;
    }

    /**
     * Return a list of the compression algorithms the server supports, when sending stuff to the client.
     *
     * @return array
     * @access public
     */
    public function getCompressionAlgorithmsServer2Client()
    {
        $this->connect();

        return $this->compression_algorithms_server_to_client;
    }

    /**
     * Return a list of the languages the server supports, when sending stuff to the client.
     *
     * @return array
     * @access public
     */
    public function getLanguagesServer2Client()
    {
        $this->connect();

        return $this->languages_server_to_client;
    }

    /**
     * Return a list of the languages the server supports, when receiving stuff from the client.
     *
     * @return array
     * @access public
     */
    public function getLanguagesClient2Server()
    {
        $this->connect();

        return $this->languages_client_to_server;
    }

    /**
     * Returns the banner message.
     *
     * Quoting from the RFC, "in some jurisdictions, sending a warning message before
     * authentication may be relevant for getting legal protection."
     *
     * @return string
     * @access public
     */
    public function getBannerMessage()
    {
        return $this->banner_message;
    }

    /**
     * Returns the server public host key.
     *
     * Caching this the first time you connect to a server and checking the result on subsequent connections
     * is recommended.  Returns false if the server signature is not signed correctly with the public host key.
     *
     * @return mixed
     * @throws \RuntimeException on badly formatted keys
     * @throws \phpseclib\Exception\NoSupportedAlgorithmsException when the key isn't in a supported format
     * @access public
     */
    public function getServerPublicHostKey()
    {
        if (!($this->bitmap & self::MASK_CONSTRUCTOR)) {
            if (!$this->connect()) {
                return false;
            }
        }

        $signature = $this->signature;
        $server_public_host_key = $this->server_public_host_key;

        if (strlen($server_public_host_key) < 4) {
            return false;
        }
        extract(unpack('Nlength', Strings::shift($server_public_host_key, 4)));
        /** @var integer $length */

        Strings::shift($server_public_host_key, $length);

        if ($this->signature_validated) {
            return $this->bitmap ?
                $this->signature_format . ' ' . Base64::encode($this->server_public_host_key) :
                false;
        }

        $this->signature_validated = true;

        switch ($this->signature_format) {
            case 'ssh-dss':
                $zero = new BigInteger();

                if (strlen($server_public_host_key) < 4) {
                    return false;
                }
                $temp = unpack('Nlength', Strings::shift($server_public_host_key, 4));
                $p = new BigInteger(Strings::shift($server_public_host_key, $temp['length']), -256);

                if (strlen($server_public_host_key) < 4) {
                    return false;
                }
                $temp = unpack('Nlength', Strings::shift($server_public_host_key, 4));
                $q = new BigInteger(Strings::shift($server_public_host_key, $temp['length']), -256);

                if (strlen($server_public_host_key) < 4) {
                    return false;
                }
                $temp = unpack('Nlength', Strings::shift($server_public_host_key, 4));
                $g = new BigInteger(Strings::shift($server_public_host_key, $temp['length']), -256);

                if (strlen($server_public_host_key) < 4) {
                    return false;
                }
                $temp = unpack('Nlength', Strings::shift($server_public_host_key, 4));
                $y = new BigInteger(Strings::shift($server_public_host_key, $temp['length']), -256);

                /* The value for 'dss_signature_blob' is encoded as a string containing
                   r, followed by s (which are 160-bit integers, without lengths or
                   padding, unsigned, and in network byte order). */
                $temp = unpack('Nlength', Strings::shift($signature, 4));
                if ($temp['length'] != 40) {
                    $this->disconnect_helper(NET_SSH2_DISCONNECT_KEY_EXCHANGE_FAILED);
                    throw new \RuntimeException('Invalid signature');
                }

                $r = new BigInteger(Strings::shift($signature, 20), 256);
                $s = new BigInteger(Strings::shift($signature, 20), 256);

                switch (true) {
                    case $r->equals($zero):
                    case $r->compare($q) >= 0:
                    case $s->equals($zero):
                    case $s->compare($q) >= 0:
                        $this->disconnect_helper(NET_SSH2_DISCONNECT_KEY_EXCHANGE_FAILED);
                        throw new \RuntimeException('Invalid signature');
                }

                $w = $s->modInverse($q);

                $u1 = $w->multiply(new BigInteger(sha1($this->exchange_hash), 16));
                list(, $u1) = $u1->divide($q);

                $u2 = $w->multiply($r);
                list(, $u2) = $u2->divide($q);

                $g = $g->modPow($u1, $p);
                $y = $y->modPow($u2, $p);

                $v = $g->multiply($y);
                list(, $v) = $v->divide($p);
                list(, $v) = $v->divide($q);

                if (!$v->equals($r)) {
                    //user_error('Bad server signature');
                    return $this->disconnect_helper(NET_SSH2_DISCONNECT_HOST_KEY_NOT_VERIFIABLE);
                }

                break;
            case 'ssh-rsa':
            case 'rsa-sha2-256':
            case 'rsa-sha2-512':
                if (strlen($server_public_host_key) < 4) {
                    return false;
                }
                $temp = unpack('Nlength', Strings::shift($server_public_host_key, 4));
                $e = new BigInteger(Strings::shift($server_public_host_key, $temp['length']), -256);

                if (strlen($server_public_host_key) < 4) {
                    return false;
                }
                $temp = unpack('Nlength', Strings::shift($server_public_host_key, 4));
                $rawN = Strings::shift($server_public_host_key, $temp['length']);
                $n = new BigInteger($rawN, -256);
                $nLength = strlen(ltrim($rawN, "\0"));

                /*
                if (strlen($signature) < 4) {
                    return false;
                }
                $temp = unpack('Nlength', Strings::shift($signature, 4));
                $signature = Strings::shift($signature, $temp['length']);

                $rsa = new RSA();
                $rsa->load(['e' => $e, 'n' => $n], 'raw');
                switch ($this->signature_format) {
                    case 'rsa-sha2-512':
                        $hash = 'sha512';
                        break;
                    case 'rsa-sha2-256':
                        $hash = 'sha256';
                        break;
                    //case 'ssh-rsa':
                    default:
                        $hash = 'sha1';
                }
                $rsa->setHash($hash);
                if (!$rsa->verify($this->exchange_hash, $signature, RSA::PADDING_PKCS1)) {
                    //user_error('Bad server signature');
                    return $this->disconnect_helper(NET_SSH2_DISCONNECT_HOST_KEY_NOT_VERIFIABLE);
                }
                */

                if (strlen($signature) < 4) {
                    return false;
                }
                $temp = unpack('Nlength', Strings::shift($signature, 4));
                $s = new BigInteger(Strings::shift($signature, $temp['length']), 256);

                // validate an RSA signature per "8.2 RSASSA-PKCS1-v1_5", "5.2.2 RSAVP1", and "9.1 EMSA-PSS" in the
                // following URL:
                // ftp://ftp.rsasecurity.com/pub/pkcs/pkcs-1/pkcs-1v2-1.pdf

                // also, see SSHRSA.c (rsa2_verifysig) in PuTTy's source.

                if ($s->compare(new BigInteger()) < 0 || $s->compare($n->subtract(new BigInteger(1))) > 0) {
                    $this->disconnect_helper(NET_SSH2_DISCONNECT_KEY_EXCHANGE_FAILED);
                    throw new \RuntimeException('Invalid signature');
                }

                $s = $s->modPow($e, $n);
                $s = $s->toBytes();

                switch ($this->signature_format) {
                    case 'rsa-sha2-512':
                        $hash = 'sha512';
                        break;
                    case 'rsa-sha2-256':
                        $hash = 'sha256';
                        break;
                    //case 'ssh-rsa':
                    default:
                        $hash = 'sha1';
                }
                $hashObj = new Hash($hash);
                switch ($this->signature_format) {
                    case 'rsa-sha2-512':
                        $h = pack('N5a*', 0x00305130, 0x0D060960, 0x86480165, 0x03040203, 0x05000440, $hashObj->hash($this->exchange_hash));
                        break;
                    case 'rsa-sha2-256':
                        $h = pack('N5a*', 0x00303130, 0x0D060960, 0x86480165, 0x03040201, 0x05000420, $hashObj->hash($this->exchange_hash));
                        break;
                    //case 'ssh-rsa':
                    default:
                        $hash = 'sha1';
                        $h = pack('N4a*', 0x00302130, 0x0906052B, 0x0E03021A, 0x05000414, $hashObj->hash($this->exchange_hash));
                }
                $h = chr(0x01) . str_repeat(chr(0xFF), $nLength - 2 - strlen($h)) . $h;

                if ($s != $h) {
                    //user_error('Bad server signature');
                    return $this->disconnect_helper(NET_SSH2_DISCONNECT_HOST_KEY_NOT_VERIFIABLE);
                }
                break;
            default:
                $this->disconnect_helper(NET_SSH2_DISCONNECT_HOST_KEY_NOT_VERIFIABLE);
                throw new NoSupportedAlgorithmsException('Unsupported signature format');
        }

        return $this->signature_format . ' ' . Base64::encode($this->server_public_host_key);
    }

    /**
     * Returns the exit status of an SSH command or false.
     *
     * @return false|int
     * @access public
     */
    public function getExitStatus()
    {
        if (is_null($this->exit_status)) {
            return false;
        }
        return $this->exit_status;
    }

    /**
     * Returns the number of columns for the terminal window size.
     *
     * @return int
     * @access public
     */
    public function getWindowColumns()
    {
        return $this->windowColumns;
    }

    /**
     * Returns the number of rows for the terminal window size.
     *
     * @return int
     * @access public
     */
    public function getWindowRows()
    {
        return $this->windowRows;
    }

    /**
     * Sets the number of columns for the terminal window size.
     *
     * @param int $value
     * @access public
     */
    public function setWindowColumns($value)
    {
        $this->windowColumns = $value;
    }

    /**
     * Sets the number of rows for the terminal window size.
     *
     * @param int $value
     * @access public
     */
    public function setWindowRows($value)
    {
        $this->windowRows = $value;
    }

    /**
     * Sets the number of columns and rows for the terminal window size.
     *
     * @param int $columns
     * @param int $rows
     * @access public
     */
    public function setWindowSize($columns = 80, $rows = 24)
    {
        $this->windowColumns = $columns;
        $this->windowRows = $rows;
    }

    /**
     * To String Magic Method
     *
     * @return string
     * @access public
     */
    public function __toString()
    {
        return $this->getResourceId();
    }

    /**
     * Get Resource ID
     *
     * We use {} because that symbols should not be in URL according to
     * {@link http://tools.ietf.org/html/rfc3986#section-2 RFC}.
     * It will safe us from any conflicts, because otherwise regexp will
     * match all alphanumeric domains.
     *
     * @return string
     */
    public function getResourceId()
    {
        return '{' . spl_object_hash($this) . '}';
    }

    /**
     * Return existing connection
     *
     * @param string $id
     *
     * @return bool|SSH2 will return false if no such connection
     */
    public static function getConnectionByResourceId($id)
    {
        return isset(self::$connections[$id]) ? self::$connections[$id] : false;
    }

    /**
     * Return all excising connections
     *
     * @return SSH2[]
     */
    public static function getConnections()
    {
        return self::$connections;
    }
}
