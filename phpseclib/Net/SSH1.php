<?php

/**
 * Pure-PHP implementation of SSHv1.
 *
 * PHP version 5
 *
 * Here's a short example of how to use this library:
 * <code>
 * <?php
 *    include 'vendor/autoload.php';
 *
 *    $ssh = new \phpseclib\Net\SSH1('www.domain.tld');
 *    if (!$ssh->login('username', 'password')) {
 *        exit('Login Failed');
 *    }
 *
 *    echo $ssh->exec('ls -la');
 * ?>
 * </code>
 *
 * Here's another short example:
 * <code>
 * <?php
 *    include 'vendor/autoload.php';
 *
 *    $ssh = new \phpseclib\Net\SSH1('www.domain.tld');
 *    if (!$ssh->login('username', 'password')) {
 *        exit('Login Failed');
 *    }
 *
 *    echo $ssh->read('username@username:~$');
 *    $ssh->write("ls -la\n");
 *    echo $ssh->read('username@username:~$');
 * ?>
 * </code>
 *
 * More information on the SSHv1 specification can be found by reading
 * {@link http://www.snailbook.com/docs/protocol-1.5.txt protocol-1.5.txt}.
 *
 * @category  Net
 * @package   SSH1
 * @author    Jim Wigginton <terrafrost@php.net>
 * @copyright 2007 Jim Wigginton
 * @license   http://www.opensource.org/licenses/mit-license.html  MIT License
 * @link      http://phpseclib.sourceforge.net
 */

namespace phpseclib\Net;

use ParagonIE\ConstantTime\Hex;
use phpseclib\Crypt\DES;
use phpseclib\Crypt\Random;
use phpseclib\Crypt\TripleDES;
use phpseclib\Math\BigInteger;
use phpseclib\Common\Functions\Strings;

/**
 * Pure-PHP implementation of SSHv1.
 *
 * @package SSH1
 * @author  Jim Wigginton <terrafrost@php.net>
 * @access  public
 */
class SSH1
{
    /**#@+
     * Encryption Methods
     *
     * @see \phpseclib\Net\SSH1::getSupportedCiphers()
     * @access public
     */
    /**
     * No encryption
     *
     * Not supported.
     */
    const CIPHER_NONE = 0;
    /**
     * IDEA in CFB mode
     *
     * Not supported.
     */
    const CIPHER_IDEA = 1;
    /**
     * DES in CBC mode
     */
    const CIPHER_DES = 2;
    /**
     * Triple-DES in CBC mode
     *
     * All implementations are required to support this
     */
    const CIPHER_3DES = 3;
    /**
     * TRI's Simple Stream encryption CBC
     *
     * Not supported nor is it defined in the official SSH1 specs.  OpenSSH, however, does define it (see cipher.h),
     * although it doesn't use it (see cipher.c)
     */
    const CIPHER_BROKEN_TSS = 4;
    /**
     * RC4
     *
     * Not supported.
     *
     * @internal According to the SSH1 specs:
     *
     *        "The first 16 bytes of the session key are used as the key for
     *         the server to client direction.  The remaining 16 bytes are used
     *         as the key for the client to server direction.  This gives
     *         independent 128-bit keys for each direction."
     *
     *     This library currently only supports encryption when the same key is being used for both directions.  This is
     *     because there's only one $crypto object.  Two could be added ($encrypt and $decrypt, perhaps).
     */
    const CIPHER_RC4 = 5;
    /**
     * Blowfish
     *
     * Not supported nor is it defined in the official SSH1 specs.  OpenSSH, however, defines it (see cipher.h) and
     * uses it (see cipher.c)
     */
    const CIPHER_BLOWFISH = 6;
    /**#@-*/

    /**#@+
     * Authentication Methods
     *
     * @see \phpseclib\Net\SSH1::getSupportedAuthentications()
     * @access public
    */
    /**
     * .rhosts or /etc/hosts.equiv
     */
    const AUTH_RHOSTS = 1;
    /**
     * pure RSA authentication
     */
    const AUTH_RSA = 2;
    /**
     * password authentication
     *
     * This is the only method that is supported by this library.
     */
    const AUTH_PASSWORD = 3;
    /**
     * .rhosts with RSA host authentication
     */
    const AUTH_RHOSTS_RSA = 4;
    /**#@-*/

    /**#@+
     * Terminal Modes
     *
     * @link http://3sp.com/content/developer/maverick-net/docs/Maverick.SSH.PseudoTerminalModesMembers.html
     * @access private
    */
    const TTY_OP_END = 0;
    /**#@-*/

    /**
     * The Response Type
     *
     * @see \phpseclib\Net\SSH1::_get_binary_packet()
     * @access private
     */
    const RESPONSE_TYPE = 1;

    /**
     * The Response Data
     *
     * @see \phpseclib\Net\SSH1::_get_binary_packet()
     * @access private
     */
    const RESPONSE_DATA = 2;

    /**#@+
     * Execution Bitmap Masks
     *
     * @see \phpseclib\Net\SSH1::bitmap
     * @access private
    */
    const MASK_CONSTRUCTOR = 0x00000001;
    const MASK_CONNECTED   = 0x00000002;
    const MASK_LOGIN       = 0x00000004;
    const MASK_SHELL       = 0x00000008;
    /**#@-*/

    /**#@+
     * @access public
     * @see \phpseclib\Net\SSH1::getLog()
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
    /**#@-*/

    /**#@+
     * @access public
     * @see \phpseclib\Net\SSH1::read()
    */
    /**
     * Returns when a string matching $expect exactly is found
     */
    const READ_SIMPLE = 1;
    /**
     * Returns when a string matching the regular expression $expect is found
     */
    const READ_REGEX = 2;
    /**#@-*/

    /**
     * The SSH identifier
     *
     * @var string
     * @access private
     */
    private $identifier = 'SSH-1.5-phpseclib';

    /**
     * The Socket Object
     *
     * @var resource
     * @access private
     */
    private $fsock;

    /**
     * The cryptography object
     *
     * @var object
     * @access private
     */
    private $crypto = false;

    /**
     * Execution Bitmap
     *
     * The bits that are set represent functions that have been called already.  This is used to determine
     * if a requisite function has been successfully executed.  If not, an error should be thrown.
     *
     * @var int
     * @access private
     */
    private $bitmap = 0;

    /**
     * The Server Key Public Exponent
     *
     * Logged for debug purposes
     *
     * @see self::getServerKeyPublicExponent()
     * @var string
     * @access private
     */
    private $server_key_public_exponent;

    /**
     * The Server Key Public Modulus
     *
     * Logged for debug purposes
     *
     * @see self::getServerKeyPublicModulus()
     * @var string
     * @access private
     */
    private $server_key_public_modulus;

    /**
     * The Host Key Public Exponent
     *
     * Logged for debug purposes
     *
     * @see self::getHostKeyPublicExponent()
     * @var string
     * @access private
     */
    private $host_key_public_exponent;

    /**
     * The Host Key Public Modulus
     *
     * Logged for debug purposes
     *
     * @see self::getHostKeyPublicModulus()
     * @var string
     * @access private
     */
    private $host_key_public_modulus;

    /**
     * Supported Ciphers
     *
     * Logged for debug purposes
     *
     * @see self::getSupportedCiphers()
     * @var array
     * @access private
     */
    private $supported_ciphers = [
        self::CIPHER_NONE       => 'No encryption',
        self::CIPHER_IDEA       => 'IDEA in CFB mode',
        self::CIPHER_DES        => 'DES in CBC mode',
        self::CIPHER_3DES       => 'Triple-DES in CBC mode',
        self::CIPHER_BROKEN_TSS => 'TRI\'s Simple Stream encryption CBC',
        self::CIPHER_RC4        => 'RC4',
        self::CIPHER_BLOWFISH   => 'Blowfish'
    ];

    /**
     * Supported Authentications
     *
     * Logged for debug purposes
     *
     * @see self::getSupportedAuthentications()
     * @var array
     * @access private
     */
    private $supported_authentications = [
        self::AUTH_RHOSTS     => '.rhosts or /etc/hosts.equiv',
        self::AUTH_RSA        => 'pure RSA authentication',
        self::AUTH_PASSWORD   => 'password authentication',
        self::AUTH_RHOSTS_RSA => '.rhosts with RSA host authentication'
    ];

    /**
     * Server Identification
     *
     * @see self::getServerIdentification()
     * @var string
     * @access private
     */
    private $server_identification = '';

    /**
     * Protocol Flags
     *
     * @see self::__construct()
     * @var array
     * @access private
     */
    private $protocol_flags = [];

    /**
     * Protocol Flag Log
     *
     * @see self::getLog()
     * @var array
     * @access private
     */
    private $protocol_flag_log = [];

    /**
     * Message Log
     *
     * @see self::getLog()
     * @var array
     * @access private
     */
    private $message_log = [];

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
     * Real-time log file wrap boolean
     *
     * @see self::_append_log()
     * @var bool
     * @access private
     */
    private $realtime_log_wrap;

    /**
     * Interactive Buffer
     *
     * @see self::read()
     * @var array
     * @access private
     */
    private $interactiveBuffer = '';

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
    private $curTimeout;

    /**
     * Log Boundary
     *
     * @see self::_format_log()
     * @access private
     */
    private $log_boundary = ':';

    /**
     * Log Long Width
     *
     * @see self::_format_log()
     * @access private
     */
    private $log_long_width = 65;

    /**
     * Log Short Width
     *
     * @see self::_format_log()
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
     * Timeout for initial connection
     *
     * Set by the constructor call. Calling setTimeout() is optional. If it's not called functions like
     * exec() won't timeout unless some PHP setting forces it too. The timeout specified in the constructor,
     * however, is non-optional. There will be a timeout, whether or not you set it. If you don't it'll be
     * 10 seconds. It is used by fsockopen() in that function.
     *
     * @see self::__construct()
     * @see self::_connect()
     * @var int
     * @access private
     */
    private $connectionTimeout;

    /**
     * Default cipher
     *
     * @see self::__construct()
     * @see self::_connect()
     * @var int
     * @access private
     */
    private $cipher;

    /**
     * Default Constructor.
     *
     * Connects to an SSHv1 server
     *
     * @param string $host
     * @param int $port
     * @param int $timeout
     * @param int $cipher
     * @return \phpseclib\Net\SSH1
     * @access public
     */
    public function __construct($host, $port = 22, $timeout = 10, $cipher = self::CIPHER_3DES)
    {
        $this->protocol_flags = [
            1  => 'NET_SSH1_MSG_DISCONNECT',
            2  => 'NET_SSH1_SMSG_PUBLIC_KEY',
            3  => 'NET_SSH1_CMSG_SESSION_KEY',
            4  => 'NET_SSH1_CMSG_USER',
            9  => 'NET_SSH1_CMSG_AUTH_PASSWORD',
            10 => 'NET_SSH1_CMSG_REQUEST_PTY',
            12 => 'NET_SSH1_CMSG_EXEC_SHELL',
            13 => 'NET_SSH1_CMSG_EXEC_CMD',
            14 => 'NET_SSH1_SMSG_SUCCESS',
            15 => 'NET_SSH1_SMSG_FAILURE',
            16 => 'NET_SSH1_CMSG_STDIN_DATA',
            17 => 'NET_SSH1_SMSG_STDOUT_DATA',
            18 => 'NET_SSH1_SMSG_STDERR_DATA',
            19 => 'NET_SSH1_CMSG_EOF',
            20 => 'NET_SSH1_SMSG_EXITSTATUS',
            33 => 'NET_SSH1_CMSG_EXIT_CONFIRMATION'
        ];

        $this->define_array($this->protocol_flags);

        $this->host = $host;
        $this->port = $port;
        $this->connectionTimeout = $timeout;
        $this->cipher = $cipher;
    }

    /**
     * Connect to an SSHv1 server
     *
     * @return bool
     * @throws \UnexpectedValueException on receipt of unexpected packets
     * @throws \RuntimeException on other errors
     * @access private
     */
    

    /**
     * Login
     *
     * @param string $username
     * @param string $password
     * @return bool
     * @throws \UnexpectedValueException on receipt of unexpected packets
     * @throws \RuntimeException on other errors
     * @access public
     */
    public function login($username, $password = '')
    {
        if (!($this->bitmap & self::MASK_CONSTRUCTOR)) {
            $this->bitmap |= self::MASK_CONSTRUCTOR;
            if (!$this->connect()) {
                return false;
            }
        }

        if (!($this->bitmap & self::MASK_CONNECTED)) {
            return false;
        }

        $data = pack('CNa*', NET_SSH1_CMSG_USER, strlen($username), $username);

        if (!$this->send_binary_packet($data)) {
            throw new \RuntimeException('Error sending SSH_CMSG_USER');
        }

        $response = $this->get_binary_packet();

        if ($response === true) {
            return false;
        }
        if ($response[self::RESPONSE_TYPE] == NET_SSH1_SMSG_SUCCESS) {
            $this->bitmap |= self::MASK_LOGIN;
            return true;
        } elseif ($response[self::RESPONSE_TYPE] != NET_SSH1_SMSG_FAILURE) {
            throw new \UnexpectedValueException('Expected SSH_SMSG_SUCCESS or SSH_SMSG_FAILURE');
        }

        $data = pack('CNa*', NET_SSH1_CMSG_AUTH_PASSWORD, strlen($password), $password);

        if (!$this->send_binary_packet($data)) {
            throw new \RuntimeException('Error sending SSH_CMSG_AUTH_PASSWORD');
        }

        // remove the username and password from the last logged packet
        if (defined('NET_SSH1_LOGGING') && NET_SSH1_LOGGING == self::LOG_COMPLEX) {
            $data = pack('CNa*', NET_SSH1_CMSG_AUTH_PASSWORD, strlen('password'), 'password');
            $this->message_log[count($this->message_log) - 1] = $data;
        }

        $response = $this->get_binary_packet();

        if ($response === true) {
            return false;
        }
        if ($response[self::RESPONSE_TYPE] == NET_SSH1_SMSG_SUCCESS) {
            $this->bitmap |= self::MASK_LOGIN;
            return true;
        } elseif ($response[self::RESPONSE_TYPE] == NET_SSH1_SMSG_FAILURE) {
            return false;
        } else {
            throw new \UnexpectedValueException('Expected SSH_SMSG_SUCCESS or SSH_SMSG_FAILURE');
        }
    }

    /**
     * Set Timeout
     *
     * $ssh->exec('ping 127.0.0.1'); on a Linux host will never return and will run indefinitely.  setTimeout() makes it so it'll timeout.
     * Setting $timeout to false or 0 will mean there is no timeout.
     *
     * @param mixed $timeout
     */
    public function setTimeout($timeout)
    {
        $this->timeout = $this->curTimeout = $timeout;
    }

    /**
     * Executes a command on a non-interactive shell, returns the output, and quits.
     *
     * An SSH1 server will close the connection after a command has been executed on a non-interactive shell.  SSH2
     * servers don't, however, this isn't an SSH2 client.  The way this works, on the server, is by initiating a
     * shell with the -s option, as discussed in the following links:
     *
     * {@link http://www.faqs.org/docs/bashman/bashref_65.html http://www.faqs.org/docs/bashman/bashref_65.html}
     * {@link http://www.faqs.org/docs/bashman/bashref_62.html http://www.faqs.org/docs/bashman/bashref_62.html}
     *
     * To execute further commands, a new \phpseclib\Net\SSH1 object will need to be created.
     *
     * Returns false on failure and the output, otherwise.
     *
     * @see self::interactiveRead()
     * @see self::interactiveWrite()
     * @param string $cmd
     * @param bool $block
     * @return mixed
     * @access public
     */
    public function exec($cmd, $block = true)
    {
        if (!($this->bitmap & self::MASK_LOGIN)) {
            throw new \RuntimeException('Operation disallowed prior to login()');
        }

        $data = pack('CNa*', NET_SSH1_CMSG_EXEC_CMD, strlen($cmd), $cmd);

        if (!$this->send_binary_packet($data)) {
            throw new \RuntimeException('Error sending SSH_CMSG_EXEC_CMD');
        }

        if (!$block) {
            return true;
        }

        $output = '';
        $response = $this->get_binary_packet();

        if ($response !== false) {
            do {
                $output.= substr($response[self::RESPONSE_DATA], 4);
                $response = $this->get_binary_packet();
            } while (is_array($response) && $response[self::RESPONSE_TYPE] != NET_SSH1_SMSG_EXITSTATUS);
        }

        $data = pack('C', NET_SSH1_CMSG_EXIT_CONFIRMATION);

        // i don't think it's really all that important if this packet gets sent or not.
        $this->send_binary_packet($data);

        fclose($this->fsock);

        // reset the execution bitmap - a new \phpseclib\Net\SSH1 object needs to be created.
        $this->bitmap = 0;

        return $output;
    }

    /**
     * Creates an interactive shell
     *
     * @see self::interactiveRead()
     * @see self::interactiveWrite()
     * @return bool
     * @throws \UnexpectedValueException on receipt of unexpected packets
     * @throws \RuntimeException on other errors
     * @access private
     */
    

    /**
     * Inputs a command into an interactive shell.
     *
     * @see self::interactiveWrite()
     * @param string $cmd
     * @return bool
     * @access public
     */
    public function write($cmd)
    {
        return $this->interactiveWrite($cmd);
    }

    /**
     * Returns the output of an interactive shell when there's a match for $expect
     *
     * $expect can take the form of a string literal or, if $mode == self::READ_REGEX,
     * a regular expression.
     *
     * @see self::write()
     * @param string $expect
     * @param int $mode
     * @return string
     * @throws \RuntimeException on connection error
     * @access public
     */
    public function read($expect, $mode = self::READ_SIMPLE)
    {
        if (!($this->bitmap & self::MASK_LOGIN)) {
            throw new \RuntimeException('Operation disallowed prior to login()');
        }

        if (!($this->bitmap & self::MASK_SHELL) && !$this->initShell()) {
            throw new \RuntimeException('Unable to initiate an interactive shell session');
        }

        $match = $expect;
        while (true) {
            if ($mode == self::READ_REGEX) {
                preg_match($expect, $this->interactiveBuffer, $matches);
                $match = isset($matches[0]) ? $matches[0] : '';
            }
            $pos = strlen($match) ? strpos($this->interactiveBuffer, $match) : false;
            if ($pos !== false) {
                return Strings::shift($this->interactiveBuffer, $pos + strlen($match));
            }
            $response = $this->get_binary_packet();

            if ($response === true) {
                return Strings::shift($this->interactiveBuffer, strlen($this->interactiveBuffer));
            }
            $this->interactiveBuffer.= substr($response[self::RESPONSE_DATA], 4);
        }
    }

    /**
     * Inputs a command into an interactive shell.
     *
     * @see self::interactiveRead()
     * @param string $cmd
     * @return bool
     * @throws \RuntimeException on connection error
     * @access public
     */
    public function interactiveWrite($cmd)
    {
        if (!($this->bitmap & self::MASK_LOGIN)) {
            throw new \RuntimeException('Operation disallowed prior to login()');
        }

        if (!($this->bitmap & self::MASK_SHELL) && !$this->initShell()) {
            throw new \RuntimeException('Unable to initiate an interactive shell session');
        }

        $data = pack('CNa*', NET_SSH1_CMSG_STDIN_DATA, strlen($cmd), $cmd);

        if (!$this->send_binary_packet($data)) {
            throw new \RuntimeException('Error sending SSH_CMSG_STDIN');
        }

        return true;
    }

    /**
     * Returns the output of an interactive shell when no more output is available.
     *
     * Requires PHP 4.3.0 or later due to the use of the stream_select() function.  If you see stuff like
     * "^[[00m", you're seeing ANSI escape codes.  According to
     * {@link http://support.microsoft.com/kb/101875 How to Enable ANSI.SYS in a Command Window}, "Windows NT
     * does not support ANSI escape sequences in Win32 Console applications", so if you're a Windows user,
     * there's not going to be much recourse.
     *
     * @see self::interactiveRead()
     * @return string
     * @throws \RuntimeException on connection error
     * @access public
     */
    public function interactiveRead()
    {
        if (!($this->bitmap & self::MASK_LOGIN)) {
            throw new \RuntimeException('Operation disallowed prior to login()');
        }

        if (!($this->bitmap & self::MASK_SHELL) && !$this->initShell()) {
            throw new \RuntimeException('Unable to initiate an interactive shell session');
        }

        $read = [$this->fsock];
        $write = $except = null;
        if (stream_select($read, $write, $except, 0)) {
            $response = $this->get_binary_packet();
            return substr($response[self::RESPONSE_DATA], 4);
        } else {
            return '';
        }
    }

    /**
     * Disconnect
     *
     * @access public
     */
    public function disconnect()
    {
        $this->disconnect_helper();
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
        $this->disconnect_helper();
    }

    /**
     * Disconnect
     *
     * @param string $msg
     * @access private
     */
    

    /**
     * Gets Binary Packets
     *
     * See 'The Binary Packet Protocol' of protocol-1.5.txt for more info.
     *
     * Also, this function could be improved upon by adding detection for the following exploit:
     * http://www.securiteam.com/securitynews/5LP042K3FY.html
     *
     * @see self::_send_binary_packet()
     * @return array|bool
     * @access private
     */
    

    /**
     * Sends Binary Packets
     *
     * Returns true on success, false on failure.
     *
     * @see self::_get_binary_packet()
     * @param string $data
     * @return bool
     * @access private
     */
    

    /**
     * Cyclic Redundancy Check (CRC)
     *
     * PHP's crc32 function is implemented slightly differently than the one that SSH v1 uses, so
     * we've reimplemented it. A more detailed discussion of the differences can be found after
     * $crc_lookup_table's initialization.
     *
     * @see self::_get_binary_packet()
     * @see self::_send_binary_packet()
     * @param string $data
     * @return int
     * @access private
     */
    

    /**
     * RSA Encrypt
     *
     * Returns mod(pow($m, $e), $n), where $n should be the product of two (large) primes $p and $q and where $e
     * should be a number with the property that gcd($e, ($p - 1) * ($q - 1)) == 1.  Could just make anything that
     * calls this call modexp, instead, but I think this makes things clearer, maybe...
     *
     * @see self::__construct()
     * @param BigInteger $m
     * @param array $key
     * @return BigInteger
     * @access private
     */
    

    /**
     * Define Array
     *
     * Takes any number of arrays whose indices are integers and whose values are strings and defines a bunch of
     * named constants from it, using the value as the name of the constant and the index as the value of the constant.
     * If any of the constants that would be defined already exists, none of the constants will be defined.
     *
     * @param $args[]
     * @access private
     */
    

    /**
     * Returns a log of the packets that have been sent and received.
     *
     * Returns a string if NET_SSH1_LOGGING == self::LOG_COMPLEX, an array if NET_SSH1_LOGGING == self::LOG_SIMPLE and false if !defined('NET_SSH1_LOGGING')
     *
     * @access public
     * @return array|false|string
     */
    public function getLog()
    {
        if (!defined('NET_SSH1_LOGGING')) {
            return false;
        }

        switch (NET_SSH1_LOGGING) {
            case self::LOG_SIMPLE:
                return $this->message_number_log;
                break;
            case self::LOG_COMPLEX:
                return $this->format_log($this->message_log, $this->protocol_flags_log);
                break;
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
     * Return the server key public exponent
     *
     * Returns, by default, the base-10 representation.  If $raw_output is set to true, returns, instead,
     * the raw bytes.  This behavior is similar to PHP's md5() function.
     *
     * @param bool $raw_output
     * @return string
     * @access public
     */
    public function getServerKeyPublicExponent($raw_output = false)
    {
        return $raw_output ? $this->server_key_public_exponent->toBytes() : $this->server_key_public_exponent->toString();
    }

    /**
     * Return the server key public modulus
     *
     * Returns, by default, the base-10 representation.  If $raw_output is set to true, returns, instead,
     * the raw bytes.  This behavior is similar to PHP's md5() function.
     *
     * @param bool $raw_output
     * @return string
     * @access public
     */
    public function getServerKeyPublicModulus($raw_output = false)
    {
        return $raw_output ? $this->server_key_public_modulus->toBytes() : $this->server_key_public_modulus->toString();
    }

    /**
     * Return the host key public exponent
     *
     * Returns, by default, the base-10 representation.  If $raw_output is set to true, returns, instead,
     * the raw bytes.  This behavior is similar to PHP's md5() function.
     *
     * @param bool $raw_output
     * @return string
     * @access public
     */
    public function getHostKeyPublicExponent($raw_output = false)
    {
        return $raw_output ? $this->host_key_public_exponent->toBytes() : $this->host_key_public_exponent->toString();
    }

    /**
     * Return the host key public modulus
     *
     * Returns, by default, the base-10 representation.  If $raw_output is set to true, returns, instead,
     * the raw bytes.  This behavior is similar to PHP's md5() function.
     *
     * @param bool $raw_output
     * @return string
     * @access public
     */
    public function getHostKeyPublicModulus($raw_output = false)
    {
        return $raw_output ? $this->host_key_public_modulus->toBytes() : $this->host_key_public_modulus->toString();
    }

    /**
     * Return a list of ciphers supported by SSH1 server.
     *
     * Just because a cipher is supported by an SSH1 server doesn't mean it's supported by this library. If $raw_output
     * is set to true, returns, instead, an array of constants.  ie. instead of ['Triple-DES in CBC mode'], you'll
     * get [self::CIPHER_3DES].
     *
     * @param bool $raw_output
     * @return array
     * @access public
     */
    public function getSupportedCiphers($raw_output = false)
    {
        return $raw_output ? array_keys($this->supported_ciphers) : array_values($this->supported_ciphers);
    }

    /**
     * Return a list of authentications supported by SSH1 server.
     *
     * Just because a cipher is supported by an SSH1 server doesn't mean it's supported by this library. If $raw_output
     * is set to true, returns, instead, an array of constants.  ie. instead of ['password authentication'], you'll
     * get [self::AUTH_PASSWORD].
     *
     * @param bool $raw_output
     * @return array
     * @access public
     */
    public function getSupportedAuthentications($raw_output = false)
    {
        return $raw_output ? array_keys($this->supported_authentications) : array_values($this->supported_authentications);
    }

    /**
     * Return the server identification.
     *
     * @return string
     * @access public
     */
    public function getServerIdentification()
    {
        return rtrim($this->server_identification);
    }

    /**
     * Logs data packets
     *
     * Makes sure that only the last 1MB worth of packets will be logged
     *
     * @param string $protocol_flags
     * @param string $message
     * @access private
     */
    
}
