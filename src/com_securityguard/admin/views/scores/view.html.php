<?php
defined('_JEXEC') or die;

class SecurityguardViewScores extends JViewLegacy
{
    protected $items;
    protected $pagination;
    protected $state;
    protected $sidebar;
    protected $threshold;

    public function display($tpl = null)
    {
        $this->state      = $this->get('State');
        $this->items      = $this->get('Items');
        $this->pagination = $this->get('Pagination');

        // Get current threshold from plugin params
        $this->threshold = 25;
        try {
            $plugin = JPluginHelper::getPlugin('system', 'securityguard');
            if ($plugin) {
                $params = new JRegistry($plugin->params);
                $this->threshold = (int)$params->get('behavior_threshold', 25);
            }
        } catch (Exception $e) {}

        $this->addToolbar();
        SecurityguardHelper::addSubmenu('scores');
        $this->sidebar = JHtmlSidebar::render();

        $doc = JFactory::getDocument();
        $doc->addStyleSheet(JURI::root() . 'media/com_securityguard/css/admin.css');

        parent::display($tpl);
    }

    protected function addToolbar()
    {
        JToolbarHelper::title(JText::_('COM_SECURITYGUARD_SCORES'), 'list');
        JToolbarHelper::custom('resetScores', 'remove', 'remove',
            'COM_SECURITYGUARD_RESET_SCORES', false);
        JToolbarHelper::preferences('com_securityguard');
    }
}
