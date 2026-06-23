<?php
defined('_JEXEC') or die;

class SecurityguardModelBlocks extends JModelList
{
    public function __construct($config = array())
    {
        if (empty($config['filter_fields'])) {
            $config['filter_fields'] = array(
                'id', 'ip', 'reason', 'blocked_until', 'attempts', 'created_at'
            );
        }
        parent::__construct($config);
    }

    protected function populateState($ordering = 'blocked_until', $direction = 'DESC')
    {
        $app = JFactory::getApplication();
        $search = $app->getUserStateFromRequest($this->context . '.filter.search', 'filter_search', '');
        $this->setState('filter.search', $search);
        parent::populateState($ordering, $direction);
    }

    protected function getListQuery()
    {
        $db = $this->getDbo();
        $query = $db->getQuery(true);

        $query->select('*')
              ->from($db->quoteName('#__securityguard_blocks'));

        $search = $this->getState('filter.search');
        if (!empty($search)) {
            $search = $db->quote('%' . $db->escape($search, true) . '%');
            $query->where('(' . $db->quoteName('ip') . ' LIKE ' . $search
                . ' OR ' . $db->quoteName('reason') . ' LIKE ' . $search . ')');
        }

        $orderCol = $this->state->get('list.ordering', 'blocked_until');
        $orderDir = $this->state->get('list.direction', 'DESC');
        $query->order($db->escape($orderCol) . ' ' . $db->escape($orderDir));

        return $query;
    }
}
