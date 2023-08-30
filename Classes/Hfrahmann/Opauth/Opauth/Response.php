<?php
namespace Hfrahmann\Opauth\Opauth;

/*                                                                        *
 * This script belongs to the Neos Flow package "Hfrahmann.Opauth".          *
 *                                                                        *
 *                                                                        */

/**
 * Class OpauthResponse
 */
class Response {

    /**
     * @var array
     */
    protected array $responseData = [];

    /**
     * @param array $responseData
     */
    public function __construct(array $responseData) {
        $this->responseData = $responseData;
    }

    /**
     * @return array
     */
    public function getRawData(): array
    {
        return $this->responseData;
    }

    /**
     * Returns the strategy name.
     *
     * @return string
     */
    public function getStrategy(): string
    {
        if(isset($this->responseData['auth']['provider']))
            return $this->responseData['auth']['provider'];
        return '';
    }

    /**
     * Returns the unique userID.
     *
     * @return string
     */
    public function getUserID(): string
    {
        if(isset($this->responseData['auth']['uid']))
            return (string)$this->responseData['auth']['uid'];
        return '';
    }

    /**
     * Return TRUE if the authentication was successful at the provider.
     *
     * @return bool
     */
    public function isAuthenticationSucceeded(): bool
    {
        if(array_key_exists('auth', $this->responseData) && array_key_exists('error', $this->responseData) === FALSE)
            return TRUE;
        return FALSE;
    }

}
