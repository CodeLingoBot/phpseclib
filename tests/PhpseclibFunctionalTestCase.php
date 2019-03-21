<?php
/**
 * @author    Andreas Fischer <bantu@phpbb.com>
 * @copyright 2014 Andreas Fischer
 * @license   http://www.opensource.org/licenses/mit-license.html  MIT License
 */

use phpseclib\Crypt\Hash;
use phpseclib\Math\BigInteger;

abstract class PhpseclibFunctionalTestCase extends PhpseclibTestCase
{
    /**
     * @param string $variable
     * @param string|null $message
     *
     * @return null
     */
    protected function requireEnv($variable, $message = null)
    {
        if ($this->_getEnv($variable) === false) {
            $msg = $message ? $message : sprintf(
                "This test requires the '%s' environment variable.",
                $this->_prefixEnvVariable($variable)
            );
            $this->markTestSkipped($msg);
        }
    }

    /**
     * @param string $variable
     *
     * @return string
     */
    protected function getEnv($variable)
    {
        $this->requireEnv($variable);
        return $this->_getEnv($variable);
    }

    

    
}
