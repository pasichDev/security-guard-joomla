<?php
defined('_JEXEC') or die;

class SecurityguardModelHoneypot extends JModelList
{
    public function __construct($config = array())
    {
        if (empty($config['filter_fields'])) {
            $config['filter_fields'] = array('id', 'ip', 'url', 'hit_at');
        }
        parent::__construct($config);
    }

    protected function populateState($ordering = 'hit_at', $direction = 'DESC')
    {
        $app = JFactory::getApplication();
        $search = $app->getUserStateFromRequest($this->context . '.filter.search', 'filter_search', '');
        $this->setState('filter.search', $search);
        parent::populateState($ordering, $direction);
    }

    protected function getListQuery()
    {
        $db = $this->getDbo();
        $query = $db->getQuery(true)
            ->select('*')
            ->from($db->quoteName('#__securityguard_honeypot'));

        $orderCol = $this->state->get('list.ordering', 'hit_at');
        $orderDir = $this->state->get('list.direction', 'DESC');
        $query->order($db->escape($orderCol) . ' ' . $db->escape($orderDir));

        return $query;
    }
}
