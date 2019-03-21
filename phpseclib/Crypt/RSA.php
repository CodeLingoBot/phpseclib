<?php

/**
 * Pure-PHP PKCS#1 (v2.1) compliant implementation of RSA.
 *
 * PHP version 5
 *
 * Here's an example of how to encrypt and decrypt text with this library:
 * <code>
 * <?php
 * include 'vendor/autoload.php';
 *
 * extract(\phpseclib\Crypt\RSA::createKey());
 *
 * $plaintext = 'terrafrost';
 *
 * $ciphertext = $publickey->encrypt($plaintext);
 *
 * echo $privatekey->decrypt($ciphertext);
 * ?>
 * </code>
 *
 * Here's an example of how to create signatures and verify signatures with this library:
 * <code>
 * <?php
 * include 'vendor/autoload.php';
 *
 * extract(\phpseclib\Crypt\RSA::createKey());
 *
 * $plaintext = 'terrafrost';
 *
 * $signature = $privatekey->sign($plaintext);
 *
 * echo $publickey->verify($plaintext, $signature) ? 'verified' : 'unverified';
 * ?>
 * </code>
 *
 * @category  Crypt
 * @package   RSA
 * @author    Jim Wigginton <terrafrost@php.net>
 * @copyright 2009 Jim Wigginton
 * @license   http://www.opensource.org/licenses/mit-license.html  MIT License
 * @link      http://phpseclib.sourceforge.net
 */

namespace phpseclib\Crypt;

use phpseclib\File\ASN1;
use phpseclib\Math\BigInteger;
use phpseclib\Common\Functions\Strings;
use phpseclib\File\ASN1\Maps\DigestInfo;
use phpseclib\Crypt\Common\AsymmetricKey;
use phpseclib\Exception\UnsupportedAlgorithmException;
use phpseclib\Exception\UnsupportedOperationException;
use phpseclib\Exception\NoKeyLoadedException;

/**
 * Pure-PHP PKCS#1 compliant implementation of RSA.
 *
 * @package RSA
 * @author  Jim Wigginton <terrafrost@php.net>
 * @access  public
 */
class RSA extends AsymmetricKey
{
    /**
     * Algorithm Name
     *
     * @var string
     * @access private
     */
    const ALGORITHM = 'RSA';

    /**#@+
     * @access public
     * @see self::encrypt()
     * @see self::decrypt()
     */
    /**
     * Use {@link http://en.wikipedia.org/wiki/Optimal_Asymmetric_Encryption_Padding Optimal Asymmetric Encryption Padding}
     * (OAEP) for encryption / decryption.
     *
     * Uses sha256 by default
     *
     * @see self::setHash()
     * @see self::setMGFHash()
     */
    const PADDING_OAEP = 1;
    /**
     * Use PKCS#1 padding.
     *
     * Although self::PADDING_OAEP / self::PADDING_PSS  offers more security, including PKCS#1 padding is necessary for purposes of backwards
     * compatibility with protocols (like SSH-1) written before OAEP's introduction.
     */
    const PADDING_PKCS1 = 2;
    /**
     * Do not use any padding
     *
     * Although this method is not recommended it can none-the-less sometimes be useful if you're trying to decrypt some legacy
     * stuff, if you're trying to diagnose why an encrypted message isn't decrypting, etc.
     */
    const PADDING_NONE = 3;
    /**
     * Use PKCS#1 padding with PKCS1 v1.5 compatibility
     *
     * A PKCS1 v2.1 encrypted message may not successfully decrypt with a PKCS1 v1.5 implementation (such as OpenSSL).
     */
    const PADDING_PKCS15_COMPAT = 6;
    /**#@-*/

    /**#@+
     * @access public
     * @see self::sign()
     * @see self::verify()
     * @see self::setHash()
     */
    /**
     * Use the Probabilistic Signature Scheme for signing
     *
     * Uses sha256 and 0 as the salt length
     *
     * @see self::setSaltLength()
     * @see self::setMGFHash()
     * @see self::setHash()
     */
    const PADDING_PSS = 4;
    /**
     * Use a relaxed version of PKCS#1 padding for signature verification
     */
    const PADDING_RELAXED_PKCS1 = 5;
    /**#@-*/

    /**
     * Modulus (ie. n)
     *
     * @var \phpseclib\Math\BigInteger
     * @access private
     */
    private $modulus;

    /**
     * Modulus length
     *
     * @var \phpseclib\Math\BigInteger
     * @access private
     */
    private $k;

    /**
     * Exponent (ie. e or d)
     *
     * @var \phpseclib\Math\BigInteger
     * @access private
     */
    private $exponent;

    /**
     * Primes for Chinese Remainder Theorem (ie. p and q)
     *
     * @var array
     * @access private
     */
    private $primes;

    /**
     * Exponents for Chinese Remainder Theorem (ie. dP and dQ)
     *
     * @var array
     * @access private
     */
    private $exponents;

    /**
     * Coefficients for Chinese Remainder Theorem (ie. qInv)
     *
     * @var array
     * @access private
     */
    private $coefficients;

    /**
     * Hash name
     *
     * @var string
     * @access private
     */
    private $hashName;

    /**
     * Length of hash function output
     *
     * @var int
     * @access private
     */
    private $hLen;

    /**
     * Length of salt
     *
     * @var int
     * @access private
     */
    private $sLen;

    /**
     * Hash function for the Mask Generation Function
     *
     * @var \phpseclib\Crypt\Hash
     * @access private
     */
    private $mgfHash;

    /**
     * Length of MGF hash function output
     *
     * @var int
     * @access private
     */
    private $mgfHLen;

    /**
     * Public Exponent
     *
     * @var mixed
     * @access private
     */
    private $publicExponent = false;

    /**
     * Public exponent
     *
     * @var int
     * @link http://en.wikipedia.org/wiki/65537_%28number%29
     * @access private
     */
    private static $defaultExponent = 65537;

    /**
     * Is the loaded key a public key?
     *
     * @var bool
     * @access private
     */
    private $isPublic = false;

    /**
     * Smallest Prime
     *
     * Per <http://cseweb.ucsd.edu/~hovav/dist/survey.pdf#page=5>, this number ought not result in primes smaller
     * than 256 bits. As a consequence if the key you're trying to create is 1024 bits and you've set smallestPrime
     * to 384 bits then you're going to get a 384 bit prime and a 640 bit prime (384 + 1024 % 384). At least if
     * engine is set to self::ENGINE_INTERNAL. If Engine is set to self::ENGINE_OPENSSL then smallest Prime is
     * ignored (ie. multi-prime RSA support is more intended as a way to speed up RSA key generation when there's
     * a chance neither gmp nor OpenSSL are installed)
     *
     * @var int
     * @access private
     */
    private static $smallestPrime = 4096;

    /**
     * Enable Blinding?
     *
     * @var bool
     * @access private
     */
    private static $enableBlinding = true;

    /**
     * The constructor
     *
     * If you want to make use of the openssl extension, you'll need to set the mode manually, yourself.  The reason
     * \phpseclib\Crypt\RSA doesn't do it is because OpenSSL doesn't fail gracefully.  openssl_pkey_new(), in particular, requires
     * openssl.cnf be present somewhere and, unfortunately, the only real way to find out is too late.
     *
     * @return \phpseclib\Crypt\RSA
     * @access public
     */
    public function __construct()
    {
        parent::__construct();

        //$this->hash = new Hash('sha256');
        $this->hLen = $this->hash->getLengthInBytes();
        $this->hashName = 'sha256';
        $this->mgfHash = new Hash('sha256');
        $this->mgfHLen = $this->mgfHash->getLengthInBytes();
    }

    /**
     * Sets the public exponent
     *
     * This will be 65537 unless changed.
     *
     * @access public
     * @param int $val
     */
    public static function setExponent($val)
    {
        self::$defaultExponent = $val;
    }

    /**
     * Sets the smallest prime number in bits
     *
     * This will be 4096 unless changed.
     *
     * @access public
     * @param int $val
     */
    public static function setSmallestPrime($val)
    {
        self::$smallestPrime = $val;
    }

    /**
     * Create public / private key pair
     *
     * Returns an array with the following two elements:
     *  - 'privatekey': The private key.
     *  - 'publickey':  The public key.
     *
     * @return array
     * @access public
     * @param int $bits
     */
    public static function createKey($bits = 2048)
    {
        self::initialize_static_variables();

        static $e;
        if (!isset($e)) {
            $e = new BigInteger(self::$defaultExponent);
        }

        $regSize = $bits >> 1; // divide by two to see how many bits P and Q would be
        if ($regSize > self::$smallestPrime) {
            $num_primes = floor($bits / self::$smallestPrime);
            $regSize = self::$smallestPrime;
        } else {
            $num_primes = 2;
        }

        $n = clone self::$one;
        $exponents = $coefficients = $primes = [];
        $lcm = [
            'top' => clone self::$one,
            'bottom' => false
        ];

        do {
            for ($i = 1; $i <= $num_primes; $i++) {
                if ($i != $num_primes) {
                    $primes[$i] = BigInteger::randomPrime($regSize);
                } else {
                    extract(BigInteger::minMaxBits($bits));
                    /** @var BigInteger $min
                     *  @var BigInteger $max
                     */
                    list($min) = $min->divide($n);
                    $min = $min->add(self::$one);
                    list($max) = $max->divide($n);
                    $primes[$i] = BigInteger::randomRangePrime($min, $max);
                }

                // the first coefficient is calculated differently from the rest
                // ie. instead of being $primes[1]->modInverse($primes[2]), it's $primes[2]->modInverse($primes[1])
                if ($i > 2) {
                    $coefficients[$i] = $n->modInverse($primes[$i]);
                }

                $n = $n->multiply($primes[$i]);

                $temp = $primes[$i]->subtract(self::$one);

                // textbook RSA implementations use Euler's totient function instead of the least common multiple.
                // see http://en.wikipedia.org/wiki/Euler%27s_totient_function
                $lcm['top'] = $lcm['top']->multiply($temp);
                $lcm['bottom'] = $lcm['bottom'] === false ? $temp : $lcm['bottom']->gcd($temp);
            }

            list($temp) = $lcm['top']->divide($lcm['bottom']);
            $gcd = $temp->gcd($e);
            $i0 = 1;
        } while (!$gcd->equals(self::$one));

        $coefficients[2] = $primes[2]->modInverse($primes[1]);

        $d = $e->modInverse($temp);

        foreach ($primes as $i => $prime) {
            $temp = $prime->subtract(self::$one);
            $exponents[$i] = $e->modInverse($temp);
        }

        // from <http://tools.ietf.org/html/rfc3447#appendix-A.1.2>:
        // RSAPrivateKey ::= SEQUENCE {
        //     version           Version,
        //     modulus           INTEGER,  -- n
        //     publicExponent    INTEGER,  -- e
        //     privateExponent   INTEGER,  -- d
        //     prime1            INTEGER,  -- p
        //     prime2            INTEGER,  -- q
        //     exponent1         INTEGER,  -- d mod (p-1)
        //     exponent2         INTEGER,  -- d mod (q-1)
        //     coefficient       INTEGER,  -- (inverse of q) mod p
        //     otherPrimeInfos   OtherPrimeInfos OPTIONAL
        // }
        $privatekey = new RSA();
        $privatekey->modulus = $n;
        $privatekey->k = $bits >> 3;
        $privatekey->publicExponent = $e;
        $privatekey->exponent = $d;
        $privatekey->privateExponent = $e;
        $privatekey->primes = $primes;
        $privatekey->exponents = $exponents;
        $privatekey->coefficients = $coefficients;

        $publickey = new RSA();
        $publickey->modulus = $n;
        $publickey->k = $bits >> 3;
        $publickey->exponent = $e;
        $publickey->publicExponent = $e;
        $publickey->isPublic = true;

        return compact('privatekey', 'publickey');
    }

    /**
     * Loads a public or private key
     *
     * Returns true on success and false on failure (ie. an incorrect password was provided or the key was malformed)
     *
     * @return bool
     * @access public
     * @param string|RSA|array $key
     * @param int|bool $type optional
     */
    public function load($key, $type = false)
    {
        if ($key instanceof RSA) {
            $this->privateKeyFormat = $key->privateKeyFormat;
            $this->publicKeyFormat = $key->publicKeyFormat;
            $this->format = $key->format;
            $this->k = $key->k;
            $this->hLen = $key->hLen;
            $this->sLen = $key->sLen;
            $this->mgfHLen = $key->mgfHLen;
            $this->password = $key->password;
            $this->isPublic = $key->isPublic;

            if (is_object($key->hash)) {
                $this->hashName = $key->hash->getHash();
                $this->hash = new Hash($this->hashName);
            }
            if (is_object($key->mgfHash)) {
                $this->mgfHash = new Hash($key->mgfHash->getHash());
            }

            if (is_object($key->modulus)) {
                $this->modulus = clone $key->modulus;
            }
            if (is_object($key->exponent)) {
                $this->exponent = clone $key->exponent;
            }
            if (is_object($key->publicExponent)) {
                $this->publicExponent = clone $key->publicExponent;
            }

            $this->primes = [];
            $this->exponents = [];
            $this->coefficients = [];

            foreach ($this->primes as $prime) {
                $this->primes[] = clone $prime;
            }
            foreach ($this->exponents as $exponent) {
                $this->exponents[] = clone $exponent;
            }
            foreach ($this->coefficients as $coefficient) {
                $this->coefficients[] = clone $coefficient;
            }

            return true;
        }

        $components = parent::load($key, $type);
        if ($components === false) {
            $this->comment = null;
            $this->modulus = null;
            $this->k = null;
            $this->exponent = null;
            $this->primes = null;
            $this->exponents = null;
            $this->coefficients = null;
            $this->publicExponent = null;
            $this->isPublic = false;

            return false;
        }

        $this->isPublic = false;
        $this->modulus = $components['modulus'];
        $this->k = $this->modulus->getLengthInBytes();
        $this->exponent = isset($components['privateExponent']) ? $components['privateExponent'] : $components['publicExponent'];
        if (isset($components['primes'])) {
            $this->primes = $components['primes'];
            $this->exponents = $components['exponents'];
            $this->coefficients = $components['coefficients'];
            $this->publicExponent = $components['publicExponent'];
        } else {
            $this->primes = [];
            $this->exponents = [];
            $this->coefficients = [];
            $this->publicExponent = false;
        }

        if ($components['isPublicKey']) {
            $this->setPublicKey();
        }

        return true;
    }

    /**
     * Returns the private key
     *
     * The private key is only returned if the currently loaded key contains the constituent prime numbers.
     *
     * @see self::getPublicKey()
     * @access public
     * @param string $type optional
     * @return mixed
     */
    public function getPrivateKey($type = 'PKCS8')
    {
        $type = self::validatePlugin('Keys', $type, 'savePrivateKey');
        if ($type === false) {
            return false;
        }

        if (empty($this->primes)) {
            return false;
        }

        return $type::savePrivateKey($this->modulus, $this->publicExponent, $this->exponent, $this->primes, $this->exponents, $this->coefficients, $this->password);

        /*
        $key = $type::savePrivateKey($this->modulus, $this->publicExponent, $this->exponent, $this->primes, $this->exponents, $this->coefficients, $this->password);
        if ($key !== false || count($this->primes) == 2) {
            return $key;
        }

        $nSize = $this->getSize() >> 1;

        $primes = [1 => clone self::$one, clone self::$one];
        $i = 1;
        foreach ($this->primes as $prime) {
            $primes[$i] = $primes[$i]->multiply($prime);
            if ($primes[$i]->getLength() >= $nSize) {
                $i++;
            }
        }

        $exponents = [];
        $coefficients = [2 => $primes[2]->modInverse($primes[1])];

        foreach ($primes as $i => $prime) {
            $temp = $prime->subtract(self::$one);
            $exponents[$i] = $this->modulus->modInverse($temp);
        }

        return $type::savePrivateKey($this->modulus, $this->publicExponent, $this->exponent, $primes, $exponents, $coefficients, $this->password);
        */
    }

    /**
     * Returns a minimalistic private key
     *
     * Returns the private key without the prime number constituents.  Structurally identical to a public key that
     * hasn't been set as the public key
     *
     * @see self::getPrivateKey()
     * @access private
     * @param string $type optional
     * @return mixed
     */
    protected function getPrivatePublicKey($type = 'PKCS8')
    {
        $type = self::validatePlugin('Keys', $type, 'savePublicKey');
        if ($type === false) {
            return false;
        }

        if (empty($this->modulus) || empty($this->exponent)) {
            return false;
        }

        $oldFormat = $this->publicKeyFormat;
        $this->publicKeyFormat = $type;
        $temp = $type::savePublicKey($this->modulus, $this->exponent);
        $this->publicKeyFormat = $oldFormat;
        return $temp;
    }

    /**
     * Returns the key size
     *
     * More specifically, this returns the size of the modulo in bits.
     *
     * @access public
     * @return int
     */
    public function getLength()
    {
        return !isset($this->modulus) ? 0 : $this->modulus->getLength();
    }

    /**
     * Returns the current engine being used
     *
     * @see self::useInternalEngine()
     * @see self::useBestEngine()
     * @access public
     * @return string
     */
    public function getEngine()
    {
        return 'PHP';
    }

    /**
     * Defines the public key
     *
     * Some private key formats define the public exponent and some don't.  Those that don't define it are problematic when
     * used in certain contexts.  For example, in SSH-2, RSA authentication works by sending the public key along with a
     * message signed by the private key to the server.  The SSH-2 server looks the public key up in an index of public keys
     * and if it's present then proceeds to verify the signature.  Problem is, if your private key doesn't include the public
     * exponent this won't work unless you manually add the public exponent. phpseclib tries to guess if the key being used
     * is the public key but in the event that it guesses incorrectly you might still want to explicitly set the key as being
     * public.
     *
     * Do note that when a new key is loaded the index will be cleared.
     *
     * Returns true on success, false on failure
     *
     * @see self::getPublicKey()
     * @access public
     * @param string|bool $key optional
     * @param int|bool $type optional
     * @return bool
     */
    public function setPublicKey($key = false, $type = false)
    {
        // if a public key has already been loaded return false
        if (!empty($this->publicExponent)) {
            return false;
        }

        if ($key === false && !empty($this->modulus)) {
            $this->isPublic = true;
            $this->publicExponent = $this->exponent;
            return true;
        }

        $components = parent::setPublicKey($key, $type);
        if ($components === false) {
            return false;
        }

        if (empty($this->modulus) || !$this->modulus->equals($components['modulus'])) {
            $this->modulus = $components['modulus'];
            $this->exponent = $this->publicExponent = $components['publicExponent'];
            $this->isPublic = true;
            return true;
        }

        $this->publicExponent = $components['publicExponent'];

        return true;
    }

    /**
     * Is the key a public key?
     *
     * @access public
     * @return bool
     */
    public function isPublicKey()
    {
        return $this->isPublic;
    }

    /**
     * Is the key a private key?
     *
     * @access public
     * @return bool
     */
    public function isPrivateKey()
    {
        return !$this->isPublic && isset($this->modulus);
    }

    /**
     * Defines the private key
     *
     * If phpseclib guessed a private key was a public key and loaded it as such it might be desirable to force
     * phpseclib to treat the key as a private key. This function will do that.
     *
     * Do note that when a new key is loaded the index will be cleared.
     *
     * Returns true on success, false on failure
     *
     * @see self::getPublicKey()
     * @access public
     * @param string|bool $key optional
     * @param int|bool $type optional
     * @return bool
     */
    public function setPrivateKey($key = false, $type = false)
    {
        if ($key === false && !empty($this->publicExponent)) {
            $this->publicExponent = false;
            $this->isPublic = false;
            return true;
        }

        $rsa = new RSA();
        if (!$rsa->load($key, $type)) {
            return false;
        }
        $rsa->publicExponent = false;
        $rsa->isPublic = false;

        // don't overwrite the old key if the new key is invalid
        $this->load($rsa);
        return true;
    }

    /**
     * Returns the public key
     *
     * The public key is only returned under two circumstances - if the private key had the public key embedded within it
     * or if the public key was set via setPublicKey().  If the currently loaded key is supposed to be the public key this
     * function won't return it since this library, for the most part, doesn't distinguish between public and private keys.
     *
     * @see self::getPrivateKey()
     * @access public
     * @param string $type optional
     * @return mixed
     */
    public function getPublicKey($type = null)
    {
        $returnObj = false;
        if ($type === null) {
            $returnObj = true;
            $type = 'PKCS8';
        }

        $type = self::validatePlugin('Keys', $type, 'savePublicKey');
        if ($type === false) {
            return false;
        }

        if (empty($this->modulus) || empty($this->publicExponent)) {
            return false;
        }

        $key = $type::savePublicKey($this->modulus, $this->publicExponent);
        if (!$returnObj) {
            return $key;
        }

        $public = clone $this;
        $public->load($key, 'PKCS8');

        return $public;
    }

    /**
     * __toString() magic method
     *
     * @access public
     * @return string
     */
    public function __toString()
    {
        try {
            $key = $this->getPrivateKey($this->privateKeyFormat);
            if (is_string($key)) {
                return $key;
            }
            $key = $this->getPrivatePublicKey($this->publicKeyFormat);
            return is_string($key) ? $key : '';
        } catch (\Exception $e) {
            return '';
        }
    }

    /**
     * Determines which hashing function should be used
     *
     * Used with signature production / verification and (if the encryption mode is self::PADDING_OAEP) encryption and
     * decryption.
     *
     * @access public
     * @param string $hash
     */
    public function setHash($hash)
    {
        // \phpseclib\Crypt\Hash supports algorithms that PKCS#1 doesn't support.  md5-96 and sha1-96, for example.
        switch (strtolower($hash)) {
            case 'md2':
            case 'md5':
            case 'sha1':
            case 'sha256':
            case 'sha384':
            case 'sha512':
            case 'sha224':
            case 'sha512/224':
            case 'sha512/256':
                $this->hash = new Hash($hash);
                $this->hashName = $hash;
                break;
            default:
                throw new UnsupportedAlgorithmException(
                    'The only supported hash algorithms are: md2, md5, sha1, sha256, sha384, sha512, sha224, sha512/224, sha512/256'
                );
        }
        $this->hLen = $this->hash->getLengthInBytes();
    }

    /**
     * Determines which hashing function should be used for the mask generation function
     *
     * The mask generation function is used by self::PADDING_OAEP and self::PADDING_PSS and although it's
     * best if Hash and MGFHash are set to the same thing this is not a requirement.
     *
     * @access public
     * @param string $hash
     */
    public function setMGFHash($hash)
    {
        // \phpseclib\Crypt\Hash supports algorithms that PKCS#1 doesn't support.  md5-96 and sha1-96, for example.
        switch ($hash) {
            case 'md2':
            case 'md5':
            case 'sha1':
            case 'sha256':
            case 'sha384':
            case 'sha512':
            case 'sha224':
            case 'sha512/224':
            case 'sha512/256':
                $this->mgfHash = new Hash($hash);
                break;
            default:
                $this->mgfHash = new Hash('sha256');
        }
        $this->mgfHLen = $this->mgfHash->getLengthInBytes();
    }

    /**
     * Determines the salt length
     *
     * To quote from {@link http://tools.ietf.org/html/rfc3447#page-38 RFC3447#page-38}:
     *
     *    Typical salt lengths in octets are hLen (the length of the output
     *    of the hash function Hash) and 0.
     *
     * @access public
     * @param int $sLen
     */
    public function setSaltLength($sLen)
    {
        $this->sLen = $sLen;
    }

    /**
     * Integer-to-Octet-String primitive
     *
     * See {@link http://tools.ietf.org/html/rfc3447#section-4.1 RFC3447#section-4.1}.
     *
     * @access private
     * @param bool|\phpseclib\Math\BigInteger $x
     * @param int $xLen
     * @return bool|string
     */
    

    /**
     * Octet-String-to-Integer primitive
     *
     * See {@link http://tools.ietf.org/html/rfc3447#section-4.2 RFC3447#section-4.2}.
     *
     * @access private
     * @param string $x
     * @return \phpseclib\Math\BigInteger
     */
    

    /**
     * Exponentiate with or without Chinese Remainder Theorem
     *
     * See {@link http://tools.ietf.org/html/rfc3447#section-5.1.1 RFC3447#section-5.1.2}.
     *
     * @access private
     * @param \phpseclib\Math\BigInteger $x
     * @return \phpseclib\Math\BigInteger
     */
    

    /**
     * Enable RSA Blinding
     *
     * @access public
     */
    public static function enableBlinding()
    {
        static::$enableBlinding = true;
    }

    /**
     * Disable RSA Blinding
     *
     * @access public
     */
    public static function disableBlinding()
    {
        static::$enableBlinding = false;
    }

    /**
     * Performs RSA Blinding
     *
     * Protects against timing attacks by employing RSA Blinding.
     * Returns $x->modPow($this->exponents[$i], $this->primes[$i])
     *
     * @access private
     * @param \phpseclib\Math\BigInteger $x
     * @param \phpseclib\Math\BigInteger $r
     * @param int $i
     * @return \phpseclib\Math\BigInteger
     */
    

    /**
     * RSAEP
     *
     * See {@link http://tools.ietf.org/html/rfc3447#section-5.1.1 RFC3447#section-5.1.1}.
     *
     * @access private
     * @param \phpseclib\Math\BigInteger $m
     * @return bool|\phpseclib\Math\BigInteger
     */
    

    /**
     * RSADP
     *
     * See {@link http://tools.ietf.org/html/rfc3447#section-5.1.2 RFC3447#section-5.1.2}.
     *
     * @access private
     * @param \phpseclib\Math\BigInteger $c
     * @return bool|\phpseclib\Math\BigInteger
     */
    

    /**
     * RSASP1
     *
     * See {@link http://tools.ietf.org/html/rfc3447#section-5.2.1 RFC3447#section-5.2.1}.
     *
     * @access private
     * @param \phpseclib\Math\BigInteger $m
     * @return bool|\phpseclib\Math\BigInteger
     */
    

    /**
     * RSAVP1
     *
     * See {@link http://tools.ietf.org/html/rfc3447#section-5.2.2 RFC3447#section-5.2.2}.
     *
     * @access private
     * @param \phpseclib\Math\BigInteger $s
     * @return bool|\phpseclib\Math\BigInteger
     */
    

    /**
     * MGF1
     *
     * See {@link http://tools.ietf.org/html/rfc3447#appendix-B.2.1 RFC3447#appendix-B.2.1}.
     *
     * @access private
     * @param string $mgfSeed
     * @param int $maskLen
     * @return string
     */
    

    /**
     * RSAES-OAEP-ENCRYPT
     *
     * See {@link http://tools.ietf.org/html/rfc3447#section-7.1.1 RFC3447#section-7.1.1} and
     * {http://en.wikipedia.org/wiki/Optimal_Asymmetric_Encryption_Padding OAES}.
     *
     * @access private
     * @param string $m
     * @param string $l
     * @throws \LengthException if strlen($m) > $this->k - 2 * $this->hLen - 2
     * @return string
     */
    

    /**
     * RSAES-OAEP-DECRYPT
     *
     * See {@link http://tools.ietf.org/html/rfc3447#section-7.1.2 RFC3447#section-7.1.2}.  The fact that the error
     * messages aren't distinguishable from one another hinders debugging, but, to quote from RFC3447#section-7.1.2:
     *
     *    Note.  Care must be taken to ensure that an opponent cannot
     *    distinguish the different error conditions in Step 3.g, whether by
     *    error message or timing, or, more generally, learn partial
     *    information about the encoded message EM.  Otherwise an opponent may
     *    be able to obtain useful information about the decryption of the
     *    ciphertext C, leading to a chosen-ciphertext attack such as the one
     *    observed by Manger [36].
     *
     * As for $l...  to quote from {@link http://tools.ietf.org/html/rfc3447#page-17 RFC3447#page-17}:
     *
     *    Both the encryption and the decryption operations of RSAES-OAEP take
     *    the value of a label L as input.  In this version of PKCS #1, L is
     *    the empty string; other uses of the label are outside the scope of
     *    this document.
     *
     * @access private
     * @param string $c
     * @param string $l
     * @return bool|string
     */
    

    /**
     * Raw Encryption / Decryption
     *
     * Doesn't use padding and is not recommended.
     *
     * @access private
     * @param string $m
     * @return bool|string
     * @throws \LengthException if strlen($m) > $this->k
     */
    

    /**
     * RSAES-PKCS1-V1_5-ENCRYPT
     *
     * See {@link http://tools.ietf.org/html/rfc3447#section-7.2.1 RFC3447#section-7.2.1}.
     *
     * @access private
     * @param string $m
     * @param bool $pkcs15_compat optional
     * @throws \LengthException if strlen($m) > $this->k - 11
     * @return bool|string
     */
    

    /**
     * RSAES-PKCS1-V1_5-DECRYPT
     *
     * See {@link http://tools.ietf.org/html/rfc3447#section-7.2.2 RFC3447#section-7.2.2}.
     *
     * For compatibility purposes, this function departs slightly from the description given in RFC3447.
     * The reason being that RFC2313#section-8.1 (PKCS#1 v1.5) states that ciphertext's encrypted by the
     * private key should have the second byte set to either 0 or 1 and that ciphertext's encrypted by the
     * public key should have the second byte set to 2.  In RFC3447 (PKCS#1 v2.1), the second byte is supposed
     * to be 2 regardless of which key is used.  For compatibility purposes, we'll just check to make sure the
     * second byte is 2 or less.  If it is, we'll accept the decrypted string as valid.
     *
     * As a consequence of this, a private key encrypted ciphertext produced with \phpseclib\Crypt\RSA may not decrypt
     * with a strictly PKCS#1 v1.5 compliant RSA implementation.  Public key encrypted ciphertext's should but
     * not private key encrypted ciphertext's.
     *
     * @access private
     * @param string $c
     * @return bool|string
     */
    

    /**
     * EMSA-PSS-ENCODE
     *
     * See {@link http://tools.ietf.org/html/rfc3447#section-9.1.1 RFC3447#section-9.1.1}.
     *
     * @return string
     * @access private
     * @param string $m
     * @throws \RuntimeException on encoding error
     * @param int $emBits
     */
    

    /**
     * EMSA-PSS-VERIFY
     *
     * See {@link http://tools.ietf.org/html/rfc3447#section-9.1.2 RFC3447#section-9.1.2}.
     *
     * @access private
     * @param string $m
     * @param string $em
     * @param int $emBits
     * @return string
     */
    

    /**
     * RSASSA-PSS-SIGN
     *
     * See {@link http://tools.ietf.org/html/rfc3447#section-8.1.1 RFC3447#section-8.1.1}.
     *
     * @access private
     * @param string $m
     * @return bool|string
     */
    

    /**
     * RSASSA-PSS-VERIFY
     *
     * See {@link http://tools.ietf.org/html/rfc3447#section-8.1.2 RFC3447#section-8.1.2}.
     *
     * @access private
     * @param string $m
     * @param string $s
     * @return bool|string
     */
    

    /**
     * EMSA-PKCS1-V1_5-ENCODE
     *
     * See {@link http://tools.ietf.org/html/rfc3447#section-9.2 RFC3447#section-9.2}.
     *
     * @access private
     * @param string $m
     * @param int $emLen
     * @throws \LengthException if the intended encoded message length is too short
     * @return string
     */
    

    /**
     * RSASSA-PKCS1-V1_5-SIGN
     *
     * See {@link http://tools.ietf.org/html/rfc3447#section-8.2.1 RFC3447#section-8.2.1}.
     *
     * @access private
     * @param string $m
     * @throws \LengthException if the RSA modulus is too short
     * @return bool|string
     */
    

    /**
     * RSASSA-PKCS1-V1_5-VERIFY
     *
     * See {@link http://tools.ietf.org/html/rfc3447#section-8.2.2 RFC3447#section-8.2.2}.
     *
     * @access private
     * @param string $m
     * @param string $s
     * @throws \LengthException if the RSA modulus is too short
     * @return bool
     */
    

    /**
     * RSASSA-PKCS1-V1_5-VERIFY (relaxed matching)
     *
     * Per {@link http://tools.ietf.org/html/rfc3447#page-43 RFC3447#page-43} PKCS1 v1.5
     * specified the use BER encoding rather than DER encoding that PKCS1 v2.0 specified.
     * This means that under rare conditions you can have a perfectly valid v1.5 signature
     * that fails to validate with _rsassa_pkcs1_v1_5_verify(). PKCS1 v2.1 also recommends
     * that if you're going to validate these types of signatures you "should indicate
     * whether the underlying BER encoding is a DER encoding and hence whether the signature
     * is valid with respect to the specification given in [PKCS1 v2.0+]". so if you do
     * $rsa->getLastPadding() and get RSA::PADDING_RELAXED_PKCS1 back instead of
     * RSA::PADDING_PKCS1... that means BER encoding was used.
     *
     * @access private
     * @param string $m
     * @param string $s
     * @return bool
     */
    

    /**
     * Encryption
     *
     * Both self::PADDING_OAEP and self::PADDING_PKCS1 both place limits on how long $plaintext can be.
     * If $plaintext exceeds those limits it will be broken up so that it does and the resultant ciphertext's will
     * be concatenated together.
     *
     * @see self::decrypt()
     * @access public
     * @param string $plaintext
     * @param int $padding optional
     * @return bool|string
     * @throws \LengthException if the RSA modulus is too short
     */
    public function encrypt($plaintext, $padding = self::PADDING_OAEP)
    {
        if (empty($this->modulus) || empty($this->exponent)) {
            throw new NoKeyLoadedException('No key has been loaded');
        }

        if (!$this->isPublic) {
            throw new UnsupportedOperationException('phpseclib does not allow the use of private keys to encrypt data');
        }

        switch ($padding) {
            case self::PADDING_NONE:
                return $this->raw_encrypt($plaintext);
            case self::PADDING_PKCS15_COMPAT:
            case self::PADDING_PKCS1:
                return $this->rsaes_pkcs1_v1_5_encrypt($plaintext, $padding == self::PADDING_PKCS15_COMPAT);
            //case self::PADDING_OAEP:
            default:
                return $this->rsaes_oaep_encrypt($plaintext);
        }
    }

    /**
     * Decryption
     *
     * @see self::encrypt()
     * @access public
     * @param string $ciphertext
     * @param int $padding optional
     * @return bool|string
     */
    public function decrypt($ciphertext, $padding = self::PADDING_OAEP)
    {
        if (empty($this->modulus) || empty($this->exponent)) {
            throw new NoKeyLoadedException('No key has been loaded');
        }

        if ($this->isPublic) {
            throw new UnsupportedOperationException('phpseclib does not allow the use of public keys to decrypt data');
        }

        switch ($padding) {
            case self::PADDING_NONE:
                return $this->raw_encrypt($ciphertext);
            case self::PADDING_PKCS1:
                return $this->rsaes_pkcs1_v1_5_decrypt($ciphertext);
            //case self::PADDING_OAEP:
            default:
                return $this->rsaes_oaep_decrypt($ciphertext);
        }
    }

    /**
     * Create a signature
     *
     * @see self::verify()
     * @access public
     * @param string $message
     * @param int $padding optional
     * @return string
     */
    public function sign($message, $padding = self::PADDING_PSS)
    {
        if (empty($this->modulus) || empty($this->exponent)) {
            throw new NoKeyLoadedException('No key has been loaded');
        }

        if ($this->isPublic) {
            throw new UnsupportedOperationException('phpseclib does not allow the use of public keys to sign data');
        }

        switch ($padding) {
            case self::PADDING_PKCS1:
            case self::PADDING_RELAXED_PKCS1:
                return $this->rsassa_pkcs1_v1_5_sign($message);
            //case self::PADDING_PSS:
            default:
                return $this->rsassa_pss_sign($message);
        }
    }

    /**
     * Verifies a signature
     *
     * @see self::sign()
     * @access public
     * @param string $message
     * @param string $signature
     * @param int $padding optional
     * @return bool
     */
    public function verify($message, $signature, $padding = self::PADDING_PSS)
    {
        if (empty($this->modulus) || empty($this->exponent)) {
            throw new NoKeyLoadedException('No key has been loaded');
        }

        if (!$this->isPublic) {
            throw new UnsupportedOperationException('phpseclib does not allow the use of private keys to verify data');
        }

        switch ($padding) {
            case self::PADDING_RELAXED_PKCS1:
                return $this->rsassa_pkcs1_v1_5_relaxed_verify($message, $signature);
            case self::PADDING_PKCS1:
                return $this->rsassa_pkcs1_v1_5_verify($message, $signature);
            //case self::PADDING_PSS:
            default:
                return $this->rsassa_pss_verify($message, $signature);
        }
    }
}
