<?php
namespace Hfrahmann\Opauth\Opauth;

/*                                                                        *
 * This script belongs to the Neos Flow package "Hfrahmann.Opauth".      *
 *                                                                        *
 *                                                                        */

use Neos\Flow\Annotations as Flow;
use Neos\Flow\Mvc\Routing\UriBuilder;
use Neos\Flow\Http\Request;
use Neos\Flow\Mvc\ActionRequest;

/**
 * Class Configuration
 * @Flow\Scope("singleton")
 */
class Configuration {

    /**
     * @var UriBuilder
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
        $httpRequest = Request::createFromEnvironment();
        $actionRequest = new ActionRequest($httpRequest);

        $this->uriBuilder = new UriBuilder();
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
        $route = $configuration['authenticationControllerRoute'];

        $opauthBasePath = $this->uriBuilder->uriFor(
            'opauth',
            array('strategy' => ''),
            $this->getRoutePart($route, '@controller'),
            $this->getRoutePart($route, '@package'),
            $this->getRoutePart($route, '@subpackage')
        );

        $opauthCallbackPath = $this->uriBuilder->uriFor(
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
        $opauthConfiguration['security_salt'] = $configuration['securitySalt'];

        // the strategy directory
        $opauthConfiguration['strategy_dir'] = $this->getStrategyDirectory($configuration);

        // import all strategy settings
        $opauthConfiguration['Strategy'] = $configuration['strategies'];

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

    /**
     * Returns the path of the directory contains the authentication strategies for opauth.
     *
     * @param array $configuration
     * @return string
     */
    protected function getStrategyDirectory(array $configuration) {
        if(isset($configuration['strategyDirectory']) && strlen($configuration['strategyDirectory']) > 0) {
            $strategyDirectory = $configuration['strategyDirectory'];
            if(substr($strategyDirectory, 1) == '/')
                return $strategyDirectory;
            else
                return FLOW_PATH_ROOT . $strategyDirectory;
        }

        // composer Libraries path
        return FLOW_PATH_PACKAGES . 'Libraries' . DIRECTORY_SEPARATOR . 'opauth' . DIRECTORY_SEPARATOR;
    }

}

?>
