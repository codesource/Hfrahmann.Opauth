<?php
namespace TYPO3\Opauth\Opauth;

/*                                                                        *
 * This script belongs to the TYPO3 Flow package "TYPO3.Opauth".          *
 *                                                                        *
 *                                                                        */

use TYPO3\Flow\Annotations as Flow;

/**
 * Class Configuration
 * @Flow\Scope("singleton")
 */
class Configuration {

    /**
     * @var \TYPO3\Flow\Mvc\Routing\UriBuilder
     */
    protected $uriBuilder;

    /**
     * @var array
     */
    protected $configuration = array();

    /**
     * Construct
     */
    public function __construct() {
        $httpRequest = \TYPO3\Flow\Http\Request::createFromEnvironment();
        $actionRequest = $httpRequest->createActionRequest();

        $this->uriBuilder = new \TYPO3\Flow\Mvc\Routing\UriBuilder();
        $this->uriBuilder->setRequest($actionRequest);
    }

    /**
     * @param array $settings
     */
    public function injectSettings(array $settings) {
        $this->configuration = $this->createConfiguration($settings);
    }

    /**
     * Returns the configuration used for the real OPAuth object.
     *
     * @return array
     */
    public function getConfiguration() {
        return $this->configuration;
    }

    /**
     * Returns the default role identifier used for the OPAuth Account.
     *
     * @return string|array|null
     */
    public function getDefaultRoleIdentifier() {
        $key = 'defaultRoleIdentifier';
        return isset($this->configuration[$key]) ? $this->configuration[$key] : NULL;
    }

    /**
     * Returns the authentication provider name that will do the authentication.
     *
     * @return string
     */
    public function getAuthenticationProviderName() {
        $key = 'authenticationProviderName';
        return isset($this->configuration[$key]) ? $this->configuration[$key] : NULL;
    }

    /**
     * Merging the configuration of the Settings.yaml with some default values for OPAuth
     *
     * @param array $configuration
     * @return array
     */
    protected function createConfiguration(array $configuration) {
        $route = $configuration['AuthenticationControllerRoute'];

        $opauthBasePath = '/' . $this->uriBuilder->uriFor(
            'opauth',
            array('strategy' => ''),
            $this->getRoutePart($route, '@controller'),
            $this->getRoutePart($route, '@package'),
            $this->getRoutePart($route, '@subpackage')
        );

        $opauthCallbackPath = '/' . $this->uriBuilder->uriFor(
            'authenticate',
            array(),
            $this->getRoutePart($route, '@controller'),
            $this->getRoutePart($route, '@package'),
            $this->getRoutePart($route, '@subpackage')
        );

        $opauthConfiguration = array();

        $opauthConfiguration['defaultRoleIdentifier'] = $configuration['defaultRoleIdentifier'];
        $opauthConfiguration['authenticationProviderName'] = $configuration['authenticationProviderName'];

        // should be created with UriBuilder
        $opauthConfiguration['path'] = $opauthBasePath;

        // should be created with UriBuilder
        $opauthConfiguration['callback_url'] = $opauthCallbackPath;

        // it must be 'post'
        $opauthConfiguration['callback_transport'] = 'post';

        // the security salt
        $opauthConfiguration['security_salt'] = $configuration['security_salt'];

        // the strategy directory
        $opauthConfiguration['strategy_dir'] = TYPO3OPAUTH_RESOURCES_PHP_PATH . 'Strategy' . DIRECTORY_SEPARATOR;

        // import all strategy settings
        $opauthConfiguration['Strategy'] = $configuration['Strategy'];

        return $opauthConfiguration;
    }

    /**
     * Returns a part of the route-array
     *
     * @param array $routeArray
     * @param string $key
     * @return string
     */
    protected function getRoutePart(&$routeArray, $key) {
        if(array_key_exists($key, $routeArray) && strlen($routeArray[$key]) > 0)
            return $routeArray[$key];
        return NULL;
    }

}

?>