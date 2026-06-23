<?php
/**
 * @package     com_securityguard
 * @author      Andriy Hodorovskyi
 * @license     GNU GPL v2 or later
 */

defined('_JEXEC') or die;

if (!JFactory::getUser()->authorise('core.manage', 'com_securityguard')) {
    throw new Exception(JText::_('JERROR_ALERTNOAUTHOR'), 403);
}

JLoader::registerPrefix('Securityguard', JPATH_COMPONENT_ADMINISTRATOR);
JLoader::register('SecurityguardHelper', JPATH_COMPONENT_ADMINISTRATOR . '/helpers/securityguard.php');

$controller = JControllerLegacy::getInstance('Securityguard');
$controller->execute(JFactory::getApplication()->input->get('task'));
$controller->redirect();
