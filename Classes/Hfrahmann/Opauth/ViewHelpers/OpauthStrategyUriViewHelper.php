<?php
namespace Hfrahmann\Opauth\ViewHelpers;

/*                                                                        *
 * This script belongs to the Neos Flow package "Hfrahmann.Opauth".          *
 *                                                                        *
 *                                                                        */

use Hfrahmann\Opauth\Opauth\Configuration;
use Neos\Fluid\Core\ViewHelper\AbstractViewHelper;
use Neos\Fluid\Core\ViewHelper;
use Neos\Flow\Annotations as Flow;

/**
 * A view helper for creating URIs for OPAuth-Actions
 *
 * = Examples =
 *
 * <code title="Defaults">
 * {namespace opauth=Hfrahmann\Opauth\ViewHelpers}
 *
 * {opauth:opauthStrategyUri(strategy:'facebook')}
 * </code>
 * <output>
 * /opauth/facebook
 * </output>
 */
class OpauthStrategyUriViewHelper extends AbstractViewHelper {

    /**
     * @var Configuration
     * @Flow\Inject
     */
    protected $opauthConfiguration;

    /**
     * @param string $strategy
     * @return string
     */
    public function render($strategy = '') {
        $opauthSettings = $this->opauthConfiguration->getConfiguration();

        $uri = $opauthSettings['path'] . $strategy;

        return $uri;
    }

}

?>