<?php
defined('_JEXEC') or die;

class SecurityguardViewDashboard extends JViewLegacy
{
    protected $stats;
    protected $topAttackers;
    protected $attackTypes;
    protected $dailyAttacks;
    protected $hourlyAttacks;
    protected $sidebar;

    public function display($tpl = null)
    {
        $this->stats         = SecurityguardHelper::getStats();
        $this->topAttackers  = SecurityguardHelper::getTopAttackers(10);
        $this->attackTypes   = SecurityguardHelper::getAttackTypes(7);
        $this->dailyAttacks  = SecurityguardHelper::getDailyAttacks(14);
        $this->hourlyAttacks = SecurityguardHelper::getHourlyAttacks(24);

        $this->addToolbar();
        SecurityguardHelper::addSubmenu('dashboard');
        $this->sidebar = JHtmlSidebar::render();

        $doc = JFactory::getDocument();
        $doc->addStyleSheet(JURI::root() . 'media/com_securityguard/css/admin.css');

        parent::display($tpl);
    }

    protected function addToolbar()
    {
        JToolbarHelper::title(JText::_('COM_SECURITYGUARD_DASHBOARD'), 'cogs');

        // v1.3.4: Export report buttons
        $exportUrl = JRoute::_('index.php?option=com_securityguard&task=exportReport', false);
        JFactory::getDocument()->addStyleDeclaration(
            '#toolbar-export-html { background: #3498db; color: #fff; }'
            . '#toolbar-export-json { background: #2ecc71; color: #fff; }'
        );
        $bar = JToolbar::getInstance('toolbar');
        $bar->appendButton('Link', 'eye', JText::_('COM_SECURITYGUARD_EXPORT_HTML'),
            $exportUrl . '&format=html&days=1');
        $bar->appendButton('Link', 'download', JText::_('COM_SECURITYGUARD_EXPORT_JSON'),
            $exportUrl . '&format=json&days=1');

        JToolbarHelper::custom('cleanup', 'eraser', 'eraser',
            'COM_SECURITYGUARD_CLEANUP_EXPIRED', false);
        JToolbarHelper::preferences('com_securityguard');
    }
}
