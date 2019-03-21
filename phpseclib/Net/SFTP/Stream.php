<?php

/**
 * SFTP Stream Wrapper
 *
 * Creates an sftp:// protocol handler that can be used with, for example, fopen(), dir(), etc.
 *
 * PHP version 5
 *
 * @category  Net
 * @package   SFTP
 * @author    Jim Wigginton <terrafrost@php.net>
 * @copyright 2013 Jim Wigginton
 * @license   http://www.opensource.org/licenses/mit-license.html  MIT License
 * @link      http://phpseclib.sourceforge.net
 */

namespace phpseclib\Net\SFTP;

use phpseclib\Crypt\RSA;
use phpseclib\Net\SFTP;
use phpseclib\Net\SSH2;

/**
 * SFTP Stream Wrapper
 *
 * @package SFTP
 * @author  Jim Wigginton <terrafrost@php.net>
 * @access  public
 */
class Stream
{
    /**
     * SFTP instances
     *
     * Rather than re-create the connection we re-use instances if possible
     *
     * @var array
     */
    static $instances;

    /**
     * SFTP instance
     *
     * @var object
     * @access private
     */
    private $sftp;

    /**
     * Path
     *
     * @var string
     * @access private
     */
    private $path;

    /**
     * Mode
     *
     * @var string
     * @access private
     */
    private $mode;

    /**
     * Position
     *
     * @var int
     * @access private
     */
    private $pos;

    /**
     * Size
     *
     * @var int
     * @access private
     */
    private $size;

    /**
     * Directory entries
     *
     * @var array
     * @access private
     */
    private $entries;

    /**
     * EOF flag
     *
     * @var bool
     * @access private
     */
    private $eof;

    /**
     * Context resource
     *
     * Technically this needs to be publicly accessible so PHP can set it directly
     *
     * @var resource
     * @access public
     */
    public $context;

    /**
     * Notification callback function
     *
     * @var callable
     * @access public
     */
    private $notification;

    /**
     * Registers this class as a URL wrapper.
     *
     * @param string $protocol The wrapper name to be registered.
     * @return bool True on success, false otherwise.
     * @access public
     */
    public static function register($protocol = 'sftp')
    {
        if (in_array($protocol, stream_get_wrappers(), true)) {
            return false;
        }
        return stream_wrapper_register($protocol, get_called_class());
    }

    /**
     * The Constructor
     *
     * @access public
     */
    public function __construct()
    {
        if (defined('NET_SFTP_STREAM_LOGGING')) {
            echo "__construct()\r\n";
        }
    }

    /**
     * Path Parser
     *
     * Extract a path from a URI and actually connect to an SSH server if appropriate
     *
     * If "notification" is set as a context parameter the message code for successful login is
     * NET_SSH2_MSG_USERAUTH_SUCCESS. For a failed login it's NET_SSH2_MSG_USERAUTH_FAILURE.
     *
     * @param string $path
     * @return string
     * @access private
     */
    

    /**
     * Opens file or URL
     *
     * @param string $path
     * @param string $mode
     * @param int $options
     * @param string $opened_path
     * @return bool
     * @access public
     */
    

    /**
     * Read from stream
     *
     * @param int $count
     * @return mixed
     * @access public
     */
    

    /**
     * Write to stream
     *
     * @param string $data
     * @return mixed
     * @access public
     */
    

    /**
     * Retrieve the current position of a stream
     *
     * @return int
     * @access public
     */
    

    /**
     * Tests for end-of-file on a file pointer
     *
     * In my testing there are four classes functions that normally effect the pointer:
     * fseek, fputs  / fwrite, fgets / fread and ftruncate.
     *
     * Only fgets / fread, however, results in feof() returning true. do fputs($fp, 'aaa') on a blank file and feof()
     * will return false. do fread($fp, 1) and feof() will then return true. do fseek($fp, 10) on ablank file and feof()
     * will return false. do fread($fp, 1) and feof() will then return true.
     *
     * @return bool
     * @access public
     */
    

    /**
     * Seeks to specific location in a stream
     *
     * @param int $offset
     * @param int $whence
     * @return bool
     * @access public
     */
    

    /**
     * Change stream options
     *
     * @param string $path
     * @param int $option
     * @param mixed $var
     * @return bool
     * @access public
     */
    

    /**
     * Retrieve the underlaying resource
     *
     * @param int $cast_as
     * @return resource
     * @access public
     */
    

    /**
     * Advisory file locking
     *
     * @param int $operation
     * @return bool
     * @access public
     */
    

    /**
     * Renames a file or directory
     *
     * Attempts to rename oldname to newname, moving it between directories if necessary.
     * If newname exists, it will be overwritten.  This is a departure from what \phpseclib\Net\SFTP
     * does.
     *
     * @param string $path_from
     * @param string $path_to
     * @return bool
     * @access public
     */
    

    /**
     * Open directory handle
     *
     * The only $options is "whether or not to enforce safe_mode (0x04)". Since safe mode was deprecated in 5.3 and
     * removed in 5.4 I'm just going to ignore it.
     *
     * Also, nlist() is the best that this function is realistically going to be able to do. When an SFTP client
     * sends a SSH_FXP_READDIR packet you don't generally get info on just one file but on multiple files. Quoting
     * the SFTP specs:
     *
     *    The SSH_FXP_NAME response has the following format:
     *
     *        uint32     id
     *        uint32     count
     *        repeats count times:
     *                string     filename
     *                string     longname
     *                ATTRS      attrs
     *
     * @param string $path
     * @param int $options
     * @return bool
     * @access public
     */
    

    /**
     * Read entry from directory handle
     *
     * @return mixed
     * @access public
     */
    

    /**
     * Rewind directory handle
     *
     * @return bool
     * @access public
     */
    

    /**
     * Close directory handle
     *
     * @return bool
     * @access public
     */
    

    /**
     * Create a directory
     *
     * Only valid $options is STREAM_MKDIR_RECURSIVE
     *
     * @param string $path
     * @param int $mode
     * @param int $options
     * @return bool
     * @access public
     */
    

    /**
     * Removes a directory
     *
     * Only valid $options is STREAM_MKDIR_RECURSIVE per <http://php.net/streamwrapper.rmdir>, however,
     * <http://php.net/rmdir>  does not have a $recursive parameter as mkdir() does so I don't know how
     * STREAM_MKDIR_RECURSIVE is supposed to be set. Also, when I try it out with rmdir() I get 8 as
     * $options. What does 8 correspond to?
     *
     * @param string $path
     * @param int $options
     * @return bool
     * @access public
     */
    

    /**
     * Flushes the output
     *
     * See <http://php.net/fflush>. Always returns true because \phpseclib\Net\SFTP doesn't cache stuff before writing
     *
     * @return bool
     * @access public
     */
    

    /**
     * Retrieve information about a file resource
     *
     * @return mixed
     * @access public
     */
    

    /**
     * Delete a file
     *
     * @param string $path
     * @return bool
     * @access public
     */
    

    /**
     * Retrieve information about a file
     *
     * Ignores the STREAM_URL_STAT_QUIET flag because the entirety of \phpseclib\Net\SFTP\Stream is quiet by default
     * might be worthwhile to reconstruct bits 12-16 (ie. the file type) if mode doesn't have them but we'll
     * cross that bridge when and if it's reached
     *
     * @param string $path
     * @param int $flags
     * @return mixed
     * @access public
     */
    

    /**
     * Truncate stream
     *
     * @param int $new_size
     * @return bool
     * @access public
     */
    

    /**
     * Change stream options
     *
     * STREAM_OPTION_WRITE_BUFFER isn't supported for the same reason stream_flush isn't.
     * The other two aren't supported because of limitations in \phpseclib\Net\SFTP.
     *
     * @param int $option
     * @param int $arg1
     * @param int $arg2
     * @return bool
     * @access public
     */
    

    /**
     * Close an resource
     *
     * @access public
     */
    

    /**
     * __call Magic Method
     *
     * When you're utilizing an SFTP stream you're not calling the methods in this class directly - PHP is calling them for you.
     * Which kinda begs the question... what methods is PHP calling and what parameters is it passing to them? This function
     * lets you figure that out.
     *
     * If NET_SFTP_STREAM_LOGGING is defined all calls will be output on the screen and then (regardless of whether or not
     * NET_SFTP_STREAM_LOGGING is enabled) the parameters will be passed through to the appropriate method.
     *
     * @param string
     * @param array
     * @return mixed
     * @access public
     */
    public function __call($name, $arguments)
    {
        if (defined('NET_SFTP_STREAM_LOGGING')) {
            echo $name . '(';
            $last = count($arguments) - 1;
            foreach ($arguments as $i => $argument) {
                var_export($argument);
                if ($i != $last) {
                    echo ',';
                }
            }
            echo ")\r\n";
        }
        $name = '_' . $name;
        if (!method_exists($this, $name)) {
            return false;
        }
        return call_user_func_array([$this, $name], $arguments);
    }
}
