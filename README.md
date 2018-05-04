Hfrahmann.Opauth
============

This is a package to use [Opauth](http://opauth.org) with your Neos Flow project.


How to use it
-------------

1. Installation

 Add this to your composer.json and do an update.
 ```json
     {
         "require":{
             "hfrahmann/opauth": "*"
         }
     }
 ```

 You can download any strategy from this list: https://github.com/opauth/opauth/wiki/List-of-strategies

 Then you have to copy the extracted directory to a folder of your choice and configure the path in the *settings.yaml*.


2. Authentication Controller

 At first you need an AuthenticationController.
 The *\Hfrahmann\Opauth\AbstractAuthenticationController* extends the original AbstractAuthenticationController from Neos Flow.

 When you extends the Opauth AbstractAuthenticationController you have to add the following methods to your AuthenticationController.

 ```php
     /**
      * This method is called when the account does not exist in the Neos Flow Account Repository.
      * You can show an addition formular for registration or add the account directly to the Account Repository.
      * If you add the account to the Repository you have to authenticate again manually.
      *
      * @param array $opauthResponseData Opauth Response with all sent data depends on the used strategy (facebook, twitter, ...)
      * @param \Neos\Flow\Security\Account $opauthAccount A pre-generated account with the Opauth data
      * @return void|string
      */
     abstract public function onOpauthAccountDoesNotExist(array $opauthResponseData, \Neos\Flow\Security\Account $opauthAccount);

     /**
      * This method is called when the authentication was cancelled or another problem occurred at the provider.
      *
      * @param array $opauthResponseData
      * @return void|string
      */
     abstract public function onOpauthAuthenticationFailure(array $opauthResponseData);
 ```


3. Routing

 The following route is necessary so that the Opauth authentication works.
 It have to be pointing to your AuthenticationController.
 You can modify the first part (before /{strategy}...) at the uriPattern like you need it.
 But the last part with the *strategy* and the *internalcallback* is important.

 ```yaml
    -
      name: 'Opauth - Strategy-Login'
      uriPattern: 'opauth/{strategy}(/{internalcallback})'
      defaults:
        '@package': 'My.Package'
        '@controller': 'Authentication'
        '@action': 'opauth' # don't change
        '@format': 'html'
        'internalcallback': '' # important
      appendExceedingArguments: true
 ```


4. Configuration

 This is the configuration for the *Settings.yaml*.
 You have configure the AuthenticationProvider pointing to the OPAuthProvider.

 In the Opauth part you have to declare the route to your AuthenticationController. (Same data like in the route from step 3)

 The *defaultRoleIdentifier* is used as the roleIdentifier for a new account.

 For the configuration of the strategies you have to specify them in the *Strategy* area.
 They are structured like the original Opauth configuration.

 ```yaml
    Neos:

      Flow:
        security:
          authentication:
            authenticationStrategy: oneToken
            providers:

              OpauthProvider:
                provider: 'Hfrahmann\Opauth\Authentication\OpauthProvider'


    Hfrahmann:

      Opauth:

        # The route the AuthenticationController.
        # Must extends the \Hfrahmann\Opauth\AbstractAuthenticationController.
        authenticationControllerRoute:
          '@package': 'My.Package'
          '@subpackage': ''
          '@controller': 'Authentication'
          # No @action required

        defaultRoleIdentifier: 'My.Package:User'
        authenticationProviderName: 'OpauthProvider' #the provider name from top

        # The security_salt must be changed before first use
        security_salt: 'LDFmiilYf8Fyw5W10rx4W1KsVrieQCnpBzzpTBWA5vJidQKDx8pMJbmw28R1C4m'
        
        strategies:
          Facebook:
            app_id: '571xxxxxxxxxxx'
            app_secret: '3daxxxxxxxxxxxxxxxxxxxxxxxxxxxx'
            scope: 'email,read_friendlists' # optional
 ```


Viewhelper
----------

There is also a ViewHelper that easily creates a URI for an Opauth strategy.

```
{namespace opauth=Hfrahmann\Opauth\ViewHelpers}

{opauth:opauthStrategyUri(strategy:'facebook')}
```

The output can be look like this: */opauth/facebook*


Example
-------

Here is an example of an AuthenticationController.

```php
//...
class AuthenticationController extends \Hfrahmann\Opauth\Controller\AbstractAuthenticationController {
  /**
   * @var \Neos\Flow\Security\AccountRepository
   * @Flow\Inject
   */
  protected $accountRepository;
  
  /**
   * @param \Neos\Flow\Mvc\ActionRequest $originalRequest The request that was intercepted by the security framework, NULL if there was none
   * @return string
   */
  protected function onAuthenticationSuccess(\Neos\Flow\Mvc\ActionRequest $originalRequest = NULL) {
    $opauthResponseData = $this->opauthResponse;
    // opauthResponseData contains the raw data of the Opauth response
  
    if ($originalRequest !== NULL) {
      $this->redirectToRequest($originalRequest);
    }
    $this->redirect('index', 'Standard', 'My.Package');
  }
  
  /**
   * @param array $opauthResponseData Opauth Response with all sent data
   * @param \Neos\Flow\Security\Account $opauthAccount A pre-generated account with the Opauth data
   * @return void
   */
  public function onOpauthAccountDoesNotExist(array $opauthResponseData, \Neos\Flow\Security\Account $opauthAccount) {
    $this->accountRepository->add($opauthAccount);
    $this->persistenceManager->persistAll();
    // Add the account to Neos Flow Account Repository.
    
    $this->authenticateAction(); // authenticate again
  }

  /**
   * This method is called when the authentication was cancelled or another problem occurred at the provider.
   *
   * @param array $opauthResponseData
   * @return void|string
   */
  public function onOpauthAuthenticationFailure(array $opauthResponseData) {
    return 'Opauth Authentication Canceled';
  }
}
```


License
-------

This project is licensed under the MIT-License.
