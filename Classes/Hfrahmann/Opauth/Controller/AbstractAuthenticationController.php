<?php
namespace Hfrahmann\Opauth\Controller;

/*                                                                        *
 * This script belongs to the Neos Flow package "Hfrahmann.Opauth".          *
 *                                                                        *
 *                                                                        */

use Hfrahmann\Opauth\Exception;
use Hfrahmann\Opauth\Opauth\Configuration;
use Hfrahmann\Opauth\Opauth\Opauth;
use Hfrahmann\Opauth\Service\OpauthAccountService;
use Neos\Flow\Mvc\Exception\NoSuchArgumentException;
use Neos\Flow\Security\Account;
use Neos\Flow\Security\Authentication\Controller\AbstractAuthenticationController as BaseAbstractAuthenticationController;

abstract class AbstractAuthenticationController extends BaseAbstractAuthenticationController
{

    /**
     * @var Opauth
     */
    private Opauth $opauth;

    /**
     * @var OpauthAccountService
     */
    private OpauthAccountService $opauthAccountService;

    /**
     * @var Configuration
     */
    private Configuration $opauthConfiguration;

    /**
     * @var bool
     */
    private bool $authenticateActionAlreadyCalled = FALSE;

    /**
     * @var array Contains the complete response data from Opauth
     */
    protected array $opauthResponse = array();

    /**
     * @param Opauth|null $opauth
     *
     * @throws NoSuchArgumentException
     */
    public function injectOpauth(?Opauth $opauth): void
    {
        $this->opauth = $opauth;
        if ($opauth !== NULL && $opauth->getResponse() !== NULL) {
            $this->opauthResponse = $opauth->getResponse()->getRawData();
        }
    }

    /**
     * @param OpauthAccountService $opauthAccountService
     */
    public function injectOpauthAccountService(OpauthAccountService $opauthAccountService): void
    {
        $this->opauthAccountService = $opauthAccountService;
    }

    /**
     * @param Configuration $opauthConfiguration
     */
    public function injectOpauthConfiguration(Configuration $opauthConfiguration): void
    {
        $this->opauthConfiguration = $opauthConfiguration;
    }

    /**
     * Run Opauth to authenticate with the given strategy.
     *
     * @param string $strategy
     * @param string $internalcallback
     * @return string
     */
    public function opauthAction(string $strategy, string $internalcallback = ''): string
    {
        $this->opauth->getOpauth()->run();

        return '';
    }

    /**
     * Overridden authenticateAction method to check for an existing account with the Opauth data.
     *
     * @return string
     *
     * @throws NoSuchArgumentException
     * @throws Exception
     */
    public function authenticateAction()
    {
        $opauthResponse = $this->opauth->getResponse();

        if (!$this->authenticateActionAlreadyCalled && $opauthResponse !== NULL) {
            $this->authenticateActionAlreadyCalled = TRUE;
            if ($opauthResponse->isAuthenticationSucceeded()) {
                $opauthAccount = $this->opauthAccountService->getAccount($opauthResponse);
                $doesAccountExists = $this->opauthAccountService->doesAccountExist($opauthAccount);

                if ($doesAccountExists === FALSE) {
                    return $this->onOpauthAccountDoesNotExist($opauthResponse->getRawData(), $opauthAccount);
                }
            } else {
                return $this->onOpauthAuthenticationFailure($opauthResponse->getRawData());
            }
        }

        return parent::authenticateAction();
    }

    /**
     * This method is called when the account does not exist in the Neos Flow Account Repository.
     * You can show an addition formular for registration or add the account directly to the Account Repository.
     * If you add the account to the Repository you have to authenticate again manually.
     *
     * @param array $opauthResponseData Opauth Response with all sent data depends on the used strategy (facebook, twitter, ...)
     * @param Account $opauthAccount A pre-generated account with the Opauth data
     * @return void|string
     */
    abstract protected function onOpauthAccountDoesNotExist(array $opauthResponseData, Account $opauthAccount);

    /**
     * This method is called when the authentication was cancelled or another problem occurred at the provider.
     *
     * @param array $opauthResponseData
     * @return void|string
     */
    abstract protected function onOpauthAuthenticationFailure(array $opauthResponseData);

}
