<?php
namespace Hfrahmann\Opauth\Opauth;

/*                                                                        *
 * This script belongs to the Neos Flow package "Hfrahmann.Opauth".          *
 *                                                                        *
 *                                                                        */

use Neos\Flow\Annotations as Flow;
use Neos\Flow\Mvc\ActionRequest;

/**
 * Class Opauth
 * @Flow\Scope("singleton")
 */
class Opauth {

    /**
     * @var \Opauth
     */
    protected $opauth;

    /**
     * @var Configuration
     * @Flow\Inject
     */
    protected $configuration;

    /**
     * @var ActionRequest
     */
    protected $actionRequest;

    /**
     * @var Response
     */
    protected $response;

    /**
     * @param ActionRequest $actionRequest
     */
    public function setActionRequest(ActionRequest $actionRequest) {
        $this->actionRequest = $actionRequest;
    }

    /**
     * Returns the real OPAuth object
     *
     * @return \Opauth
     */
    public function getOpauth() {
        if($this->opauth === NULL) {
            $this->workarounds();
            $configuration = $this->configuration->getConfiguration();
            $this->opauth = new \Opauth($configuration, FALSE);
        }
        return $this->opauth;
    }

    /**
     * Returns an Response object containing the OPAuth data
     *
     * @return Response
     */
    public function getResponse() {
        if($this->actionRequest instanceof ActionRequest && $this->actionRequest->hasArgument('opauth')) {
            $data = $this->actionRequest->getArgument('opauth');
            $response = unserialize(base64_decode($data));
            $this->response = new Response($response);
        }

        return $this->response;
    }

    /**
     * Some Workarounds for some strategies.
     *
     * @return void
     */
    protected function workarounds() {

        // When canceling a Twitter-Authentication, Flow returns a notice.
        if(isset($_REQUEST['oauth_token']) == FALSE)
            $_REQUEST['oauth_token'] = '';
    }

}

?>