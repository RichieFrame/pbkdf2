<?php
/**
 * In this file you find the encryption class
 *
 * PHP Version 5.2.13
 *
 * @category Magento
 * @package  Ikonoshirt_Pbkdf2
 * @author   Fabian Blechschmidt <fabian.blechschmidt@ikonoshirt.de>
 * @license  http://www.ikonoshirt.de/stuff/licenses/beerware-fabian.txt THE BEER-WARE LICENSE
 * @version  GIT: <git_id>
 * @link     https://github.com/ikonoshirt/pbkdf2
 * @php
 */

/**
 * Encryption class
 *
 * @category Magento
 * @package  Ikonoshirt_Pbkdf2
 * @author   Fabian Blechschmidt <fabian.blechschmidt@ikonoshirt.de>
 * @license  http://www.ikonoshirt.de/stuff/licenses/beerware-fabian.txt THE BEER-WARE LICENSE
 * @link     https://github.com/ikonoshirt/pbkdf2
 */
class Ikonoshirt_Pbkdf2_Model_Encryption
{
    /**
     * pbkdf2 iterations
     * default 10000
     *
     * @var integer
     */
    protected $_iterations;

    /**
     * pbkdf2 hash algorithm
     * default sha512
     *
     * @var string
     */
    protected $_hashAlgorithm;

    /**
     * pbkdf2 key length in octets
     * default 64
     *
     * @var integer
     */
    protected $_keyLength;

    /**
     * pbkdf2 salt length
     * default 16, should be at least 8
     *
     * @var integer
     */
    protected $_saltLength;

    /**
     * pbkdf2 legacy check to support old md5 hashes
     * default false
     *
     * @var boolean
     */
    protected $_checkLegacy;

    /**
     * Prefix to avoid having the same salt in different
     * applications/shops you can define a prefix
     *
     * @var string
     */
    protected $_prefix;
    /**
     * the stub which is used to replace the old encryption model
     *
     * @var Ikonoshirt_Pbkdf2_Model_Stub_Interface
     */
    protected $_encryptionStub;

    /**
     * overwrite default attributes with configuration settings
     *
     * @param array $arguments
     *
     * @return \Ikonoshirt_Pbkdf2_Model_Encryption
     */
    public function __construct(array $arguments)
    {
        $this->_encryptionStub = $arguments[0];
        $this->_iterations
        = (int)Mage::getStoreConfig('ikonoshirt/pbkdf2/iterations');
        $this->_hashAlgorithm
        = Mage::getStoreConfig('ikonoshirt/pbkdf2/hash_algorithm');
        $this->_keyLength
        = (int)Mage::getStoreConfig('ikonoshirt/pbkdf2/key_length');
        $this->_saltLength
        = (int)Mage::getStoreConfig('ikonoshirt/pbkdf2/salt_length');
        $this->_prefix
        = (string)Mage::getStoreConfig('ikonoshirt/pbkdf2/prefix');
        $this->_checkLegacy
        = (boolean)Mage::getStoreConfig(
            'ikonoshirt/pbkdf2/check_legacy_hash'
        );
    }


    /**
     * Generate a [salted] hash.
     *
     * $salt can be:
     * false - old Mage_Core_Model_Encryption::hash() function will be used
     * integer - a random with specified length will be generated
     * string - use the given salt for _pbkdf2
     *
     * @param string $plaintext
     * @param mixed  $salt
     *
     * @return string
     */
    public function getHash($plaintext, $salt = false)
    {
        if (false === $salt) {
            // if no salt was passed, use the old method
            return $this->_encryptionStub->hash($plaintext);
        }

        if (is_integer($salt)) {
            // check for minimum length
            if ($salt < $this->_saltLength) {
                $salt = $this->_saltLength;
            }
            $randomStringForSalt = $this->_getRandomString($salt);
            $salt = $this->_prefix . $randomStringForSalt;

        }

        return $this->_pbkdf2(
            $this->_hashAlgorithm,
            $plaintext,
            $salt,
            $this->_iterations,
            $this->_keyLength
        ) . ':' .$salt;
    }


    /**
     * Validate hash against hashing method (with or without salt)
     *
     * @param string $password
     * @param string $hash
     *
     * @return bool
     * @throws Mage_Core_Exception
     */
    public function validateHash($password, $hash)
    {
        $hashArr = explode(':', $hash);
        switch (count($hashArr)) {
            case 1:
            return $this->_encryptionStub->hash($password) === $hash;
            case 2:
                if ($this->_pbkdf2(
                    $this->_hashAlgorithm, $password,
                    $hashArr[1], $this->_iterations,
                    $this->_keyLength
                ) === $hashArr[0]
                ) {
                    return true;
                }
            return
                $this->_checkLegacy
                && $this->_encryptionStub->validateLegacyHash(
                    $password, $hash
                );
        }
        Mage::throwException('Invalid hash.');
    }


    /**
     * Generate encoded digest in BPMHASH format
     *
     * @param string $plaintext
     * @param string $salt
     *
     * @return string
     */
    protected function _bpmhashDigest($plaintext, $salt)
    {
        $digest = '';

        if (function_exists('hash_pbkdf2')) {
            $digest = $this->$_base64url_encode(hash_pbkdf2(
                $this->_hashAlgorithm,
                $this->_singleHash($this->_hashAlgorithm, $plaintext, true),
                $salt,
                $this->_iterations,
                $this->_keyLength,
                true
            ));
        } else {
            $digest = $this->$_base64url_encode($this->_pbkdf2(
                $this->_hashAlgorithm,
                $this->_singleHash($this->_hashAlgorithm, $plaintext, true),
                $salt,
                $this->_iterations,
                $this->_keyLength,
                true
            ));
        }

        return $digest;
    }


    /**
     * Generate raw PBKDF2 digest
     *
     * @param string $plaintext
     * @param string $salt
     *
     * @return string
     */
    protected function _pbkdf2Digest($plaintext, $salt)
    {
        $digest = '';

        if (function_exists('hash_pbkdf2')) {
            $digest = hash_pbkdf2(
                $this->_hashAlgorithm,
                $plaintext,
                $salt,
                $this->_iterations,
                $this->_keyLength,
                true
            );
        } else {
            $digest = $this->_pbkdf2(
                $this->_hashAlgorithm,
                $plaintext,
                $salt,
                $this->_iterations,
                $this->_keyLength,
                true
            );
        }

        return $digest;
    }


    /**
     * PBKDF2 key derivation function as defined by RSA's PKCS #5:
     * https://www.ietf.org/rfc/rfc2898.txt
     *
     * Test vectors can be found here: https://www.ietf.org/rfc/rfc6070.txt
     *
     * This implementation of PBKDF2 was originally created by defuse.ca
     * With improvements by variations-of-shadow.com
     *
     * @var string $algorithm - The hash algorithm to use. Recommended: SHA256
     * @var string $password  - The password.
     * @var string $salt      - A salt that is unique to the password.
     * @var int    $count     - Iteration count. Higher is better, but slower.
     *                          Recommended: At least 1024.
     * @var        $keyLength - The length of the derived key in bytes.
     * @var        $rawOutput - If true, the key is returned in raw binary
     *                          format. Hex encoded otherwise.
     *
     *
     * @return string $keyLength-byte key derived from the password and salt.
     */
    protected function _pbkdf2(
        $algorithm, $password, $salt, $count,
        $keyLength, $rawOutput = false
    )
    {
        $algorithm = strtolower($algorithm);
        if (!in_array($algorithm, hash_algos(), true)) {
            Mage::throwException(
                'PBKDF2 ERROR: Invalid hash algorithm ' . $algorithm
            );
        }
        if ($count <= 0 || $keyLength <= 0) {
            Mage::throwException('PBKDF2 ERROR: Invalid parameters.');
        }

        $hashLength = strlen(hash($algorithm, "", true));
        $blockCount = ceil($keyLength / $hashLength);

        // See Section 5.2 of the RFC 2898
        if ($keyLength > (pow(2, 32) - 1) * $hashLength) {
            Mage::throwException(
                'PBKDF2 ERROR: Invalid parameter: derived key too long.'
            );
        }

        $output = "";
        for ($i = 1; $i <= $blockCount; $i++) {
            // $i encoded as 4 bytes, big endian.
            $last = $salt . pack("N", $i);
            // first iteration
            $last = $xorsum = hash_hmac($algorithm, $last, $password, true);
            // perform the other $count - 1 iterations
            for ($j = 1; $j < $count; $j++) {
                $xorsum
                ^= ($last = hash_hmac($algorithm, $last, $password, true));
            }
            $output .= $xorsum;
        }

        if ($rawOutput) {
            return substr($output, 0, $keyLength);
        } else {
            return bin2hex(substr($output, 0, $keyLength));
        }
    }


    /**
     * Get random string (ported from Magento 2 with several changes)
     * UNTESTED
     *
     * @param int         $length
     * @return string
     */
    protected function _getRandomString($length)
    {
        $str = '';
        $rstr = '';

        if (function_exists('openssl_random_pseudo_bytes')) {
            // use openssl lib if it is installed

            $bytes = openssl_random_pseudo_bytes(2 * $length);

        } elseif ($fp = @fopen('/dev/urandom', 'rb')) {
            // attempt to use /dev/urandom if it exists but openssl isn't available

            $bytes = @fread($fp, 2 * $length);
            fclose($fp);

        } else {
            // fallback to mt_rand() if all else fails
            // this should be logged as an error

            Mage::log('_getRandomString MT Fallback', null, 'pbkdf2.log');
            $chars = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
            mt_srand();
            for ($i = 0, $lc = strlen($chars) - 1; $i < $length; $i++) {
                $rand = mt_rand(0, $lc); // random integer from 0 to $lc
                $str .= $chars[$rand];
            }
            $rstr = $str;

        }

        if ('' === $rstr) {
            // encode, filter, and truncate random bytes if final output is not set
            $rstr = substr(rtrim(str_replace(array('+', '/'),array('', ''),base64_encode($bytes)), '='),0,$length);
        }

        return $rstr;
    }


    /**
     * Calculate a cryptographic hash using native PHP function instead of Magento hash()
     *
     * @param string         $algorithm
     * @param string         $data
     * @param bool           $rawOutput = false
     * @return string
     */
    protected function _singleHash($algorithm, $data, $rawOutput = false)
    {
        $ctx = hash_init($algorithm);
        hash_update($ctx, $data);
        return hash_final($ctx,true,$rawOutput);
    }


    /**
     * Generate URL safe B64 encoded string
     *
     * @param string         $data
     * @return string
     */
    protected function _base64url_encode($data)
    {
        return rtrim(strtr(base64_encode($data), '+/', '-_'), '=');
    }
