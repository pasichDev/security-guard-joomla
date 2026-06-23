<?php
defined('_JEXEC') or die;

class SecurityguardViewTraffic extends JViewLegacy
{
    protected $stats;
    protected $sidebar;
    protected $timeRange = 24; // hours
    protected $bucketInterval = 300;

    public function display($tpl = null)
    {
        $app = JFactory::getApplication();
        $this->timeRange = (int)$app->input->getInt('range', 24);
        if ($this->timeRange < 1) $this->timeRange = 24;

        // Get bucket interval from plugin
        $this->bucketInterval = 300;
        try {
            $plugin = JPluginHelper::getPlugin('system', 'securityguard');
            if ($plugin) {
                $params = new JRegistry($plugin->params);
                $this->bucketInterval = (int)$params->get('traffic_interval', 300);
            }
        } catch (Exception $e) {}

        $this->stats = SecurityguardHelper::getTrafficSummary($this->timeRange);

        $this->addToolbar();
        SecurityguardHelper::addSubmenu('traffic');
        $this->sidebar = JHtmlSidebar::render();

        $doc = JFactory::getDocument();
        $doc->addStyleSheet(JURI::root() . 'media/com_securityguard/css/admin.css');

        parent::display($tpl);
    }

    protected function addToolbar()
    {
        JToolbarHelper::title(JText::_('COM_SECURITYGUARD_TRAFFIC_MONITOR'), 'chart-line');
        JToolbarHelper::preferences('com_securityguard');
    }
}
