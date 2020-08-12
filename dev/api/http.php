<?php
/*********************************************************************
    http.php

    HTTP controller for the osTicket API

    Jared Hancock
    Copyright (c)  2006-2013 osTicket
    http://www.osticket.com

    Released under the GNU General Public License WITHOUT ANY WARRANTY.
    See LICENSE.TXT for details.

    vim: expandtab sw=4 ts=4 sts=4:
**********************************************************************/
// Use sessions — it's important for SSO authentication, which uses
// /api/auth/ext
define('DISABLE_SESSION', false);

require 'api.inc.php';

# Include the main api urls
require_once INCLUDE_DIR."class.dispatcher.php";

$dispatcher = patterns('',

        //url_post("^/tickets\.(?P<format>xml|json|email)$", array('api.tickets.php:TicketApiController','create')),

        //ticket creation with session (we use only json format)
        url_post("^/tickets/create\.(?P<format>json)$", array('api.tickets.php:TicketApiController','create')),

        //user reply to his own ticket
        url_post("^/tickets/replyUser\.(?P<format>json)$", array('api.tickets.php:TicketApiController','postUserReply')),

        //staff replies to a user ticket with the updated status
        //url_post("^/tickets/reply\.(?P<format>json)$", array('api.tickets.php:TicketApiController','postReply')),

        // RESTful
        //url_get("^/tickets$", array('api.tickets.php:TicketApiController','restGetTickets')),
        //url_get("^/tickets/(?P<ticket_number>\d{6})$", array('api.tickets.php:TicketApiController','restGetTicket')),

        //get a ticket info by session
        url_get("^/tickets/ticketInfo$", array('api.tickets.php:TicketApiController','getTicketInfo')),

        //get staff tickets using parameter (staff username)
        //url_get("^/tickets/staffTickets$", array('api.tickets.php:TicketApiController','getStaffTickets')),

        //get user tickets using parameter (user e-mail)
        //url_get("^/tickets/clientTickets$", array('api.tickets.php:TicketApiController','getClientTickets')),

        //get user tickets by session
        url_get("^/tickets/tickets$", array('api.tickets.php:TicketApiController','getUserSessionTickets')),

        //get account info by session
        url_get("^/tickets/account$", array('api.tickets.php:TicketApiController','getAccountInfo')),

        //get dynamic form fields when a user makes a ticket
        url_get("^/tickets/userFormFields$", array('api.tickets.php:TicketApiController','getUserFormFields')),

        //get help topics
        //url_get("^/tickets/helpTopics$", array('api.tickets.php:TicketApiController','getHelpTopics')),

        //get help topic info using parameter (help topic id)
        url_get("^/tickets/helpTopicInfo$", array('api.tickets.php:TicketApiController','getHelpTopicInfo')),

        //get public sub-departments using parameter (parent department id)
        url_get("^/tickets/publicChildDepartments$", array('api.tickets.php:TicketApiController','getPublicChildDepartments')),

        //get department help topics using two parameters (department id and includeParentsHelpTopics)
        url_get("^/tickets/departmentHelpTopics$", array('api.tickets.php:TicketApiController','getDepartmentHelpTopics'))


        # Should stay disabled until there's an api key permission for ticket deletion
        //url_delete("^/tickets/(?P<ticket_number>\d{6})$", array('api.tickets.php:TicketApiController','restDelete')),
        //url('^/tasks/', patterns('',url_post("^cron$", array('api.cron.php:CronApiController', 'execute'))))

        );

Signal::send('api', $dispatcher);

# Call the respective function
print $dispatcher->resolve($ost->get_path_info());
?>
