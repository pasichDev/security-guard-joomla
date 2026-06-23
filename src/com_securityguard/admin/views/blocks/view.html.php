<?php
defined('_JEXEC') or die;

class SecurityguardViewBlocks extends JViewLegacy
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
        SecurityguardHelper::addSubmenu('blocks');
        $this->sidebar = JHtmlSidebar::render();

        $doc = JFactory::getDocument();
        $doc->addStyleSheet(JURI::root() . 'media/com_securityguard/css/admin.css');

        parent::display($tpl);
    }

    protected function addToolbar()
    {
        JToolbarHelper::title(JText::_('COM_SECURITYGUARD_BLOCKS'), 'lock');
        JToolbarHelper::custom('clearBlocks', 'remove', 'remove',
            'COM_SECURITYGUARD_CLEAR_ALL_BLOCKS', false);
        JToolbarHelper::custom('cleanup', 'eraser', 'eraser',
            'COM_SECURITYGUARD_CLEANUP_EXPIRED', false);
        JToolbarHelper::preferences('com_securityguard');
    }
}
