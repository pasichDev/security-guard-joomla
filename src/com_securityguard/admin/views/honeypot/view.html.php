<?php
defined('_JEXEC') or die;

class SecurityguardViewHoneypot extends JViewLegacy
{
    protected $items;
    protected $pagination;
    protected $state;
    protected $sidebar;

    public function display($tpl = null)
    {
        $this->state      = $this->get('State');
        $this->items      = $this->get('Items');
        $this->pagination = $this->get('Pagination');

        $this->addToolbar();
        SecurityguardHelper::addSubmenu('honeypot');
        $this->sidebar = JHtmlSidebar::render();

        $doc = JFactory::getDocument();
        $doc->addStyleSheet(JURI::root() . 'media/com_securityguard/css/admin.css');

        parent::display($tpl);
    }

    protected function addToolbar()
    {
        JToolbarHelper::title(JText::_('COM_SECURITYGUARD_HONEYPOT'), 'attention');
        JToolbarHelper::custom('clearHoneypot', 'remove', 'remove',
            'COM_SECURITYGUARD_CLEAR_HONEYPOT', false);
        JToolbarHelper::preferences('com_securityguard');
    }
}
