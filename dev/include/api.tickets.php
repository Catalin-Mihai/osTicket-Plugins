<?php

include_once INCLUDE_DIR.'class.api.php';
include_once INCLUDE_DIR.'class.ticket.php';

// DEFINE THIS IF YOU ARE TESTING WITHOUT EXTERNAL AUTH
define("NO_AUTH", true);

class TicketApiController extends ApiController {

    # Supported arguments -- anything else is an error. These items will be
    # inspected _after_ the fixup() method of the ApiXxxDataParser classes
    # so that all supported input formats should be supported
    function getRequestStructure($format, $data=null) {
        $supported = array(
            "alert", "autorespond", "source", "topicId",
            "attachments" => array("*" =>
                array("name", "type", "data", "encoding", "size")
            ),
            "message", "ip", "priorityId",
            "system_emails" => array(
                "*" => "*"
            ),
            "thread_entry_recipients" => array (
                "*" => array("to", "cc")
            )
        );
        # Fetch dynamic form field names for the given help topic and add
        # the names to the supported request structure
        if (isset($data['topicId'])
                && ($topic = Topic::lookup($data['topicId']))
                && ($forms = $topic->getForms())) {
            foreach ($forms as $form)
                foreach ($form->getDynamicFields() as $field)
                    $supported[] = $field->get('name');
        }

        # Ticket form fields
        # TODO: Support userId for existing user
        if(($form = TicketForm::getInstance()))
            foreach ($form->getFields() as $field)
                $supported[] = $field->get('name');

        # User form fields
        if(($form = UserForm::getInstance()))
            foreach ($form->getFields() as $field)
                $supported[] = $field->get('name');

        if(!strcasecmp($format, 'email')) {
            $supported = array_merge($supported, array('header', 'mid',
                'emailId', 'to-email-id', 'ticketId', 'reply-to', 'reply-to-name',
                'in-reply-to', 'references', 'thread-type', 'system_emails',
                'mailflags' => array('bounce', 'auto-reply', 'spam', 'viral'),
                'recipients' => array('*' => array('name', 'email', 'source'))
                ));

            $supported['attachments']['*'][] = 'cid';
        }

        return $supported;
    }


    /* Validate data - overwrites parent's validator for additional validations. */
    function validate(&$data, $format, $strict=true) {
        global $ost;

        //Call parent to Validate the structure
        if(!parent::validate($data, $format, $strict) && $strict)
            $this->exerr(400, __('Unexpected or invalid data received'));

        // Use the settings on the thread entry on the ticket details
        // form to validate the attachments in the email
        $tform = TicketForm::objects()->one()->getForm();
        $messageField = $tform->getField('message');
        $fileField = $messageField->getWidget()->getAttachments();

        // Nuke attachments IF API files are not allowed.
        if (!$messageField->isAttachmentsEnabled())
            $data['attachments'] = array();

        //Validate attachments: Do error checking... soft fail - set the error and pass on the request.
        if ($data['attachments'] && is_array($data['attachments'])) {
            foreach($data['attachments'] as &$file) {
                if ($file['encoding'] && !strcasecmp($file['encoding'], 'base64')) {
                    if(!($file['data'] = base64_decode($file['data'], true)))
                        $file['error'] = sprintf(__('%s: Poorly encoded base64 data'),
                            Format::htmlchars($file['name']));
                }
                // Validate and save immediately
                try {
                    $F = $fileField->uploadAttachment($file);
                    $file['id'] = $F->getId();
                }
                catch (FileUploadError $ex) {
                    $name = $file['name'];
                    $file = array();
                    $file['error'] = Format::htmlchars($name) . ': ' . $ex->getMessage();
                }
            }
            unset($file);
        }

        return true;
    }


    /* IN USE -- create a new ticket */
    function create($format) {

        try{

            //bypass os-ticket API Key authorization (we don't use it anymore)
            //if(!($key=$this->requireApiKey()) || !$key->canCreateTickets())
                //return $this->exerr(401, __('API key not authorized'));

            $this->checkUnibucAPIAuth();

            //only users which have an account should make tickets
            //if an agent want`s to make a ticket then he should create an user account
            $this->checkAndGetUser($this->getUserEmail(),false);

            /*
            //we don't use ticket creation by email or xml. Only json.

            if(!strcasecmp($format, 'email')) {
                # Handle remote piped emails - could be a reply...etc.
                $ticket = $this->processEmail();
            } else {
                # Parse request body
                $ticket = $this->createTicket($this->getRequest($format));
            }
            */


            // Parse request body and create ticket
            $data = $this->getRequest($format);

            //check if ticket message contains something
            if(!isset($data['message']) || $data['message'] == "")
                return $this->exerr(401, __("Ticket contains no message"));


            $ticket = null;
            $ticket = $this->createTicket($data);

            if(!$ticket)
                return $this->exerr(500, __("Unable to create new ticket: unknown error"));

            $this->response(201, $ticket->getNumber());
        }
        catch (Throwable $e){
            $msg = $e-> getMessage();
            $result =  array('ERROR' => 'Ticket was not created' ,'status_code' => 'FAILURE', 'status_msg' => $msg);
            $this->response(500, json_encode($result), $contentType="application/json");
        }

    }


    /* private helper functions */
    function createTicket($data) {

        # Pull off some meta-data
        $alert       = (bool) (isset($data['alert'])       ? $data['alert']       : true);
        $autorespond = (bool) (isset($data['autorespond']) ? $data['autorespond'] : true);

        # Assign default value to source if not defined, or defined as NULL
        $data['source'] = isset($data['source']) ? $data['source'] : 'API';

        # Create the ticket with the data (attempt to anyway)
        $errors = array();

        $ticket = Ticket::create($data, $errors, $data['source'], $autorespond, $alert);
        # Return errors (?)
        if (count($errors)) {
            if(isset($errors['errno']) && $errors['errno'] == 403)
                return $this->exerr(403, __('Ticket denied'));
            else
                return $this->exerr(
                        400,
                        __("Unable to create new ticket: validation errors").":\n"
                        .Format::array_implode(": ", "\n", $errors)
                        );
        } elseif (!$ticket) {
            return $this->exerr(500, __("Unable to create new ticket: unknown error"));
        }

        return $ticket;
    }


    function processEmail($data=false) {

        if (!$data)
            $data = $this->getEmailRequest();

        $seen = false;
        if (($entry = ThreadEntry::lookupByEmailHeaders($data, $seen))
            && ($message = $entry->postEmail($data))
        ) {
            if ($message instanceof ThreadEntry) {
                return $message->getThread()->getObject();
            }
            else if ($seen) {
                // Email has been processed previously
                return $entry->getThread()->getObject();
            }
        }

        // Allow continuation of thread without initial message or note
        elseif (($thread = Thread::lookupByEmailHeaders($data))
            && ($message = $thread->postEmail($data))
        ) {
            return $thread->getObject();
        }

        // All emails which do not appear to be part of an existing thread
        // will always create new "Tickets". All other objects will need to
        // be created via the web interface or the API
        return $this->createTicket($data);
    }


    /* specific function to authenticate in API for unibuc purpose */
    private function checkUnibucAPIAuth(){

        if(defined("NO_AUTH"))
            return true;

        /* User is able to authenticate in API only if is logged in with an microsoft account and
           his e-mail address is a valid unibuc e-mail address */

        //bypass os-ticket API Key authorization (we don't use it anymore)
        //if(!($key=$this->requireApiKey()))
            //return $this->exerr(401, __('API key not authorized'));


        // Make authorization for API using unibuc criteria

        //check if is auth with microsoft
        if (!isset($_SESSION[':oauth']))
            return $this->exerr(401, __('Not authorized without microsoft'));


        //check for '.unibuc.ro' pattern
        $unibucEmailPattern = '/^[a-zA-Z0-9.]+@[a-zA-Z]+\.[unibuc]+\.[ro]/';
        $userEmail = $_SESSION[':oauth']['email']; //email unibuc

        if (!preg_match($unibucEmailPattern, $userEmail))
            return $this->exerr(401, __('Not authorized. No unibuc mail! '));

    }


    /* private helper to get email using session */
    private function getUserEmail(){

        if(defined("NO_AUTH"))
            return "test.api@test.com";
        else
            return $_SESSION[':oauth']['email'];

    }


    /* private helper to check if user exists using email from session */
    private function checkAndGetUser($userEmail,$getUser){

        $user = User::lookupByEmail($userEmail);

        if(!$user)
            return $this->exerr(401, __('User not found'));

        if($getUser)
            return $user;
    }


    /* IN USE -- get ticket info by session e-mail using parameter (ticket number) */
    function getTicketInfo() {
        try{

            $this->checkUnibucAPIAuth();

            // check if user exists
            $user = $this->checkAndGetUser($this->getUserEmail(),true);

            $ticket_number = $_REQUEST['ticketNumber'];
            if (!($ticket_number))
                return $this->exerr(422, __('missing ticketNumber parameter '));


            // Checks for valid ticket number
            if (!is_numeric($ticket_number))
                return $this->exerr(401, __('Invalid ticket number'));


            // Checks for existing ticket with that number
            $id = Ticket::getIdByNumber($ticket_number);

            if ($id <= 0)
                return $this->exerr(401, __('Ticket not found'));

            // Load ticket and send response
            $ticket = Ticket::lookup($id);

            //check if is a ticket for current user
            if(!$ticket->checkUserAccess(new EndUser($user)))
                return $this->exerr(401, __('Not authorized. No access for this ticket'));

            $result =  array('ticket'=> $ticket ,'status_code' => '0', 'status_msg' => 'ticket details retrieved successfully');
            $result_code = 200;
            $this->response($result_code, json_encode($result ), $contentType="application/json");

        }
        catch ( Throwable $e){
            $msg = $e-> getMessage();
            $result =  array('ticket'=> array() ,'status_code' => 'FAILURE', 'status_msg' => $msg);
            $this->response(500, json_encode($result), $contentType="application/json");
        }

    }

    /**
     * RESTful GET ticket collection
     *
     * Pagination is made wit Range header.
     * i.e.
     *      Range: items=0-    <-- request all items
     *      Range: items=0-9   <-- request first 10 items
     *      Range: items 10-19 <-- request items 11 to 20
     *
     * Pagination status is given on Content-Range header.
     * i.e.
     *      Content-Range items 0-9/100 <-- first 10 items retrieved, 100 total items.
     *
     * TODO: Add filtering support
     *
     */
    /* NOT IN USE */
    function restGetTickets() {

        if(!($key=$this->requireApiKey()))
            return $this->exerr(401, __('API key not authorized'));

        # Build query
        $qfields = array('number', 'created', 'updated', 'closed');
        $q = 'SELECT ';
        foreach ($qfields as $f) {
            $q.=$f.',';
        }
        $q=rtrim($q, ',');
        $qfrom = ' FROM '.TICKET_TABLE;
        $q .= $qfrom;

        $res = db_query($q);

        header("TEST:".$q);

        mysqli_free_result($res2);
        unset($row);
        $tickets = array();
        $result_rows = $res->num_rows ;
        // header("rowNum :  ${result_rows}");
        for ($row_no = 0; $row_no < $result_rows; $row_no++) {
            $res->data_seek($row_no);
            $row = $res->fetch_assoc();
            $ticket = array();
            foreach ($qfields as $f) {
                array_push($ticket, array($f, $row[$f]));
            }
            array_push($ticket, array('href', '/api/tickets/'.$row['number']));
            array_push($tickets, $ticket);
        }

        $result_code = 200;
        $this->response($result_code, json_encode($tickets), $contentType = "application/json");
    }


    /* NOT IN USE - get staff tickets using parameter (staff username)*/
    function getStaffTickets(){

        try{

            if (! ($key = $this->requireApiKey()))
                return $this->exerr(401, __('API key not authorized'));

            $staffUserName = $_REQUEST['staffUserName'];
            if (! ($staffUserName))
                return $this->exerr(422, __('missing staffUserName parameter '));
            mysqli_set_charset('utf8mb4');
            $staff = Staff::lookup(array(
                'username' => $staffUserName
            ));

            $myTickets = Ticket::objects()->filter(array(
                'staff_id' => $staff->getId()
            ))
                ->all();


            $tickets = array();
            foreach ($myTickets as $ticket) {
                array_push($tickets, $ticket);

            }




            $result_code = 200;
            $result =  array('tickets'=> $tickets ,'status_code' => '0', 'status_msg' => 'success');
            $this->response($result_code, json_encode($result),
                $contentType="application/json");

        }
        catch ( Throwable $e){
            $msg = $e-> getMessage();
            $result =  array('tickets'=> array() ,'status_code' => 'FAILURE', 'status_msg' => $msg);
            $this->response($result_code, json_encode($result),
                $contentType="application/json");
        }
    }


    /* NOT IN USE -- get user tickets using parameter (user e-mail) */
    function getClientTickets() {
        try{
            if(!($key=$this->requireApiKey()))
                return $this->exerr(401, __('API key not authorized'));

            mysqli_set_charset('utf8mb4');

            $clientUserName = $_REQUEST['clientUserMail'];
            if(!($clientUserName))
                return $this->exerr(422, __('missing clientUserMail parameter '));
            $user = TicketUser::lookupByEmail($clientUserName);

            $myTickets = Ticket::objects()->filter(array('user_id' => $user->getId()))->all();

            $tickets = array();
            foreach ($myTickets as $ticket) {
                array_push($tickets, $ticket);
            }


            $result_code = 200;
            $result =  array('tickets'=> $tickets ,'status_code' => '0', 'status_msg' => 'success');

            $this->response($result_code, json_encode($result ),
                $contentType="application/json");

        }
        catch ( Throwable $e){
            $msg = $e-> getMessage();
            $result =  array('tickets'=> array() ,'status_code' => 'FAILURE', 'status_msg' => $msg);
            $this->response(500, json_encode($result),
                $contentType="application/json");
        }
    }


    /* IN USE -- get user tickets by session */
    function getUserSessionTickets() {
        try {

            $this->checkUnibucAPIAuth();

            $user = $this->checkAndGetUser($this->getUserEmail(),true);

            //global $db;
            //mysqli_set_charset($db, 'utf8mb4');

            $myTickets = Ticket::objects()->filter(array('user_id' => $user->getId()))->all();

            $tickets = array();
            foreach ($myTickets as $ticket) {
                $formattedTicket = json_encode($ticket);
                $formattedTicket = json_decode($formattedTicket);

                $tmp = array(
                    'ticket_number' => $formattedTicket->ticket_number,
                    'subject' => $formattedTicket->subject,
                    'ticket_status' => $formattedTicket->ticket_status,
                    'department' => $formattedTicket->department,
                    'create_timestamp' => $formattedTicket->create_timestamp
                );

                array_push($tickets, $tmp);
            }

            $result_code = 200;
            $result =  array('tickets'=> $tickets ,'status_code' => '0', 'status_msg' => 'success');

            $this->response($result_code, json_encode($result ), $contentType="application/json");

        }
        catch ( Throwable $e){
            $msg = $e-> getMessage();
            $result =  array('tickets'=> array() ,'status_code' => 'FAILURE', 'status_msg' => $msg);
            $this->response(500, json_encode($result), $contentType="application/json");
        }
    }


    /* IN USE -- get account info by session */
    function getAccountInfo() {
        try{

            $this->checkUnibucAPIAuth();

            $this->checkAndGetUser($this->getUserEmail(),false);

            //global $db;
            //mysqli_set_charset($db, 'utf8mb4');

            $result_code = 200;
            $tmp =  array('account_email' => $this->getUserEmail(),
                        'account_display_name' => $_SESSION[':oauth']['profile']['displayName'],
                        'organization' => $_SESSION[':oauth']['profile']['jobTitle']);

            $result = array(
                'account_info' => $tmp,
                'status_code' => '0',
                'status_msg' => 'success'
            );

            $this->response($result_code, json_encode($result), $contentType="application/json");

        }
        catch ( Throwable $e){
            $msg = $e-> getMessage();
            $result =  array('status_code' => 'FAILURE', 'status_msg' => $msg);
            $this->response(500, json_encode($result), $contentType="application/json");
        }
    }


    /* NOT IN USE -- staff replies to client ticket with the updated status */
    function postReply($format) {
        try{

            if(!($key=$this->requireApiKey()) || !$key->canCreateTickets())
                return $this->exerr(401, __('API key not authorized'));

            $data = $this->getRequest($format);

            # Checks for existing ticket with that number
            $id = Ticket::getIdByNumber($data['ticketNumber']);
            if ($id <= 0)
                return $this->exerr(401, __('Ticket not found'));

            $data['id']=$id;
            $staff = Staff::lookup(array('username'=>$data['staffUserName']));
            $data['staffId']= $staff -> getId();
            $data['poster'] = $staff;

            $ticket=Ticket::lookup($id);
            $errors = array();
            $response = $ticket->postReply($data , $errors);


            if(!$response)
                return $this->exerr(500, __("Unable to reply to this ticket: unknown error"));

            $location_base = '/api/tickets/';
            // header('Location: '.$location_base.$ticket->getNumber());
            // $this->response(201, $ticket->getNumber());
            $result =  array( 'status_code' => '0', 'status_msg' => 'reply posted successfully');
            $result_code=200;
            $this->response($result_code, json_encode($result ),
                $contentType="application/json");

        }
        catch ( Throwable $e){
            $msg = $e-> getMessage();
            $result =  array('tickets'=> array() ,'status_code' => 'FAILURE', 'status_msg' => $msg);
            $this->response(500, json_encode($result),
                $contentType="application/json");
        }
    }


    /* IN USE -- post user reply */
    function postUserReply($format) {

        try{
            //bypass os-ticket API Key authorization (we don't use it anymore)
            //if(!($key=$this->requireApiKey()) || !$key->canCreateTickets())
              //return $this->exerr(401, __('API key not authorized'));

            $this->checkUnibucAPIAuth();

            //check if user exist
            $user = $this->checkAndGetUser($this->getUserEmail(),true);

            $data = $this->getRequest($format);
            //error_log(print_r($data),3,"C:\\erori.log");


            # Checks for existing ticket with that number
            $id = Ticket::getIdByNumber($data['ticketNumber']);

            if ($id <= 0)
                return $this->exerr(401, __("Ticket not found"));


            //extract the ticket (here ticket should exists but double check again after ticket extraction)
            $ticket = Ticket::lookupByNumber($data['ticketNumber']);

            if(!$ticket)
                return $this->exerr(401, __("Ticket not found. Unknown error"));

            //check if is a ticket for current user
            if(!$ticket->checkUserAccess(new EndUser($user)))
                return $this->exerr(401, __('Not authorized. No access for this ticket'));


            //check if message contains something
            if(!isset($data['message']) || $data['message'] == "")
                return $this->exerr(401, __("No message to post"));


            //prepare message for posting
            $vars = array(
                'userId' => $user->getId(),
                'poster' => (string) $user->getName(),
                'message' => $data['message'],
                'ip' => $data['ip_address']
            );

            //if(isset($data['draft_id']))
                //$vars['draft_id'] = $data['draft_id'];


            if(isset($data['attachments']))
                $vars['files'] = $data['attachments'];

            //error_log(print_r($vars),3,"C:\\erori.log");

            if(!($ticket->postMessage($vars, 'Web')))
                return $this->exerr(500, __("Unable to post the message: unknown error"));

            $result_code = 200;
            $this->response($result_code, $ticket->getNumber());

        }
        catch ( Throwable $e){
            $msg = $e-> getMessage();
            $result =  array('tickets'=> array() ,'status_code' => 'FAILURE', 'status_msg' => $msg);
            $this->response(500, json_encode($result),$contentType="application/json");
        }

    }


    /* private helper for parsing configuration fields */
    private function parseConfiguration($configuration){

        if(isset($configuration)) {

            $result = array();
            $jsonDecode = json_decode($configuration);

            foreach ($jsonDecode as $key => $value){

                // special case for choices field for 'ChoiceField' type
                if($key == "choices"){

                    // https://www.php.net/manual/ro/function.strpos.php
                    if(strpos($value,PHP_EOL) !== false){

                        $organizations = explode(PHP_EOL, $value);
                        $tmp = array();

                        //get organizations for this 'ChoiceField' ( as key -> value )
                        foreach ($organizations as $org){
                            // $aux[0] is the key and $aux[1] is the value
                            // the key is up to the first two point
                            $aux = explode(":",$org,2);
                            $tmp[$aux[0]] = $aux[1];
                        }

                        $result[$key] = $tmp;
                    }
                    else{
                        $result[$key] = $value;
                    }

                    continue;
                }

                $result[$key] = $value;

            }

           return $result;
        }

        return null;
    }


    /* private helper to parse 'field_info' for our purpose */
    private function parseEnabledFormsToJSON($enabledForms){

        $result = array();

        foreach($enabledForms as $form){

            $configuration = $this->parseConfiguration($form['field_info']['configuration']);

            $tmp =  array(
                'field_name' => $form['field_name'],
                'required' => $form['field_info']['required'],
                'label' => $form['field_info']['label'],
                'id' => $form['field_info']['id'],
                'configuration' => $configuration,
            );

            array_push($result,$tmp);
        }

        //print("<pre>".print_r($result, true)."</pre>");
        return $result;

    }


    /* private helper to get only supported forms */
    private function filterForms($enabledForms){

        $filteredForms = array();
        $minIndexDefaultSummaryForm = PHP_INT_MAX;

        // keep only default issue summary field (has the smallest id)
        foreach ($enabledForms as $form){
            if($form['field_name'] == 'TextboxField'){
                if($form['field_info']['id'] < $minIndexDefaultSummaryForm){
                    $minIndexDefaultSummaryForm = $form['field_info']['id'];
                }
            }
        }

        foreach ($enabledForms as $form){

            switch ($form['field_name']){
                case 'ChoiceField':
                case 'ThreadEntryField':
                    array_push($filteredForms,$form);
                    break;
                case 'TextboxField':
                    if($minIndexDefaultSummaryForm == $form['field_info']['id']){
                        array_push($filteredForms,$form);
                    }
                    break;
            }
        }

        //print("<pre>".print_r($filteredForms, true)."</pre>");
        return $filteredForms;
    }


    /* private helper to obtain only enabled fields for a help topic (an enabled field is a field which will appear on page).
    For more info check  'help-topics -> click on a help topic -> click on forms tab'  in admin panel */
    private function getEnabledForms($topic){

        //get all form fields
        $allTopicForms = $topic->getForms();
        $enabledForms = array();

        foreach ($allTopicForms[0]->_fields->getIterator() as $it){

            //save only enabled form fields
            if(!$it->parent->_disabled){

                $tmp =  array(
                    'field_name' => get_class($it),
                    'field_info' => $it->ht);

                array_push($enabledForms,$tmp);
            }

        }

        //print("<pre>".print_r($enabledForms, true)."</pre>");
        return $enabledForms;
    }


    /* IN USE - get user forms by parameter (help topic) -- every help topic has his custom forms */
    function getUserFormFields(){

        try{

            $this->checkUnibucAPIAuth();

            $this->checkAndGetUser($this->getUserEmail(),false);

            //validate help topic id
            $helpTopicId = $_REQUEST['helpTopicId'];

            if (!($helpTopicId))
                return $this->exerr(422, __('missing help topic id parameter '));


            # Checks for valid help topic id number
            if (!is_numeric($helpTopicId))
                return $this->exerr(401, __('Invalid help topic id number'));


            # Checks for existing topic with that id
            $topic = Topic::Lookup($helpTopicId);

            if (!$topic)
                return $this->exerr(401, __('Topic not found'));


            $enabledForms = $this->getEnabledForms($topic);
            $filteredForms = $this->filterForms($enabledForms);
            $jsonFormat = $this->parseEnabledFormsToJSON($filteredForms);

            $result = array(
                'form_fields' => $jsonFormat,
                'status_code' => '0',
                'status_msg' => 'success'
            );

            $result_code = 200;
            $this->response($result_code, json_encode($result), $contentType="application/json");

        }
        catch ( Throwable $e){
            $msg = $e-> getMessage();
            $result =  array('tickets'=> array() ,'status_code' => 'FAILURE', 'status_msg' => $msg);
            $this->response(500, json_encode($result), $contentType="application/json");
        }


    }


    /* NOT IN USE - get all help topics */
    function getHelpTopics(){

        try{

            if(!($key=$this->requireApiKey()))
                return $this->exerr(401, __('API key not authorized'));

            $this->checkUnibucAPIAuth();

            //check if user exist
            $this->checkAndGetUser($this->getUserEmail(),true);

            $topics = Topic::getHelpTopics($publicOnly=true, $disabled=false);

            if(!$topics){
                return $this->exerr(401, __('Topics not found'));
            }

            $helpTopics = array();

            foreach ($topics as $key => $value){
                $tmp = array(
                    'id' => $key,
                    'name' => $value
                );

                array_push($helpTopics,$tmp);
            }

            $result = array(
                'help_topics' => $helpTopics,
                'status_code' => '0',
                'status_msg' => 'success'
            );

            $result_code = 200;
            $this->response($result_code, json_encode($result), $contentType="application/json");

        }
        catch ( Throwable $e){
            $msg = $e-> getMessage();
            $result =  array('tickets'=> array() ,'status_code' => 'FAILURE', 'status_msg' => $msg);
            $this->response(500, json_encode($result), $contentType="application/json");
        }

    }


    /* IN USE - get help topic info using parameter (help topic id) */
    function getHelpTopicInfo(){

        try{

            $this->checkUnibucAPIAuth();

            $this->checkAndGetUser($this->getUserEmail(),false);

            $topic_id = $_REQUEST['topicId'];
            if (!($topic_id))
                return $this->exerr(422, __('missing topicId parameter '));


            # Checks for valid ticket number
            if (!is_numeric($topic_id))
                return $this->exerr(401, __('Invalid topicId'));


            # Checks for existing ticket with that number
            $topic = Topic::lookup($topic_id);

            if (!$topic)
                return $this->exerr(401, __('Topic not found'));

            $result = array(
                'topic_info' => $topic->ht,
                'status_code' => '0',
                'status_msg' => 'success'
            );

            $result_code = 200;
            $this->response($result_code, json_encode($result), $contentType="application/json");

        }
        catch ( Throwable $e){
            $msg = $e-> getMessage();
            $result =  array('tickets'=> array() ,'status_code' => 'FAILURE', 'status_msg' => $msg);
            $this->response(500, json_encode($result), $contentType="application/json");
        }

    }


    /* IN USE -- get public sub-departments using parameter (parent department id) */
    function getPublicChildDepartments(){

        try {

            $this->checkUnibucAPIAuth();

            //check if user exists
            $this->checkAndGetUser($this->getUserEmail(),false);

            //convention for root deps
            $ROOT_DEPARTMENT = -1;

            $parentDepartmentId = $_REQUEST['departmentId'];
            if (!($parentDepartmentId))
                return $this->exerr(422, __('missing department Id parameter '));


            // Checks for valid department number
            if (!is_numeric($parentDepartmentId))
                return $this->exerr(401, __('Invalid department id number'));


            // check if department exist
            if ($parentDepartmentId != $ROOT_DEPARTMENT && !Dept::Lookup($parentDepartmentId))
                return $this->exerr(401, __('Department not found'));


            $subDepartments = array();

            //get all deps if exists
            if ($deps = Dept::getDepartments()) {

                foreach ($deps as $id => $name) {

                    $dep = Dept::Lookup($id);
                    $tmp = array(
                        'id' => $dep->getId(),
                        'name' => $dep->getName()
                    );

                    // we get only public deps
                    if ($dep->isPublic() && $dep->isActive()) {

                        // if we call api with $ROOT_DEPARTMENT value we want only root deps
                        if ($parentDepartmentId == $ROOT_DEPARTMENT) {

                            // we take only deps with no parent
                            if (!$dep->getParent()) {
                                array_push($subDepartments, $tmp);
                            }

                        } else {

                            // if we call api with $parentDepartmentId value > 0
                            // we take all direct sub-departments for $parentDepartmentId
                            if ($dep->getParent() && $dep->getParent()->getId() == $parentDepartmentId) {
                                    array_push($subDepartments, $tmp);
                            }
                        }

                    }
                }
            }

            // if we have 0 elements => no deps was added in previous if =>
            //  means that this $parentDepartmentId is a leaf in the tree => we mark this $parentDepartmentId as a leaf

            if(count($subDepartments) == 0) {
                $finalChild = true;
            }else{
                $finalChild = false;
            }

            $parentInfo = array(
                'finalChild' => $finalChild,
                'id' => $parentDepartmentId
            );

            $result = array(
                'parent_info' => $parentInfo,
                'sub_departments' => $subDepartments,
                'status_code' => '0',
                'status_msg' => 'success'
            );

            $result_code = 200;
            $this->response($result_code, json_encode($result), $contentType = "application/json");

        } catch (Throwable $e) {
            $msg = $e->getMessage();
            $result = array('departments' => array(), 'status_code' => 'FAILURE', 'status_msg' => $msg);
            $this->response(500, json_encode($result),$contentType = "application/json");
        }
    }


    /* private helper to obtain all parents for a $childDepartment (all nodes from $childDepartment to the root are saved) */
    private function getAllParents($childDepartment){

        $depsArray = array();

        while (true){

            $tmp = array(
                'id' => $childDepartment->getId(),
                'name' => $childDepartment->getName()
            );

            if(!$childDepartment->getParent()){
                array_push($depsArray,$tmp);
                return $depsArray;
            }

            array_push($depsArray,$tmp);
            $childDepartment = $childDepartment->getParent();

        }

    }


    /* IN USE -- get department help topics using two parameters (department id and includeParentsHelpTopics) */
    function getDepartmentHelpTopics(){
        try {

            $this->checkUnibucAPIAuth();

            //check if user exists
            $this->checkAndGetUser($this->getUserEmail(),false);


            $departmentId = $_REQUEST['departmentId'];
            $includeParentsHelpTopics = $_REQUEST['includeParentsHelpTopics'];

            if (!($departmentId) || !($includeParentsHelpTopics))
                return $this->exerr(422, __('missing departmentId parameter or includeParentsHelpTopics parameter'));

            if($includeParentsHelpTopics != 'false' && $includeParentsHelpTopics != 'true')
                return $this->exerr(422, __('$includeParentsHelpTopics must be true or false'));


            // Checks for valid departmentId number
            if (!is_numeric($departmentId))
                return $this->exerr(401, __('Invalid department id number'));


            // check if department exist
            if (!Dept::Lookup($departmentId))
                return $this->exerr(401, __('Department not found'));


            $topics = Topic::getHelpTopics($publicOnly=true, $disabled=false);

            if(!$topics){
                return $this->exerr(401, __('Topics not found'));
            }


            if($includeParentsHelpTopics == 'true')
                $deps = $this->getAllParents(Dept::Lookup($departmentId));
            else
                $deps = Dept::Lookup($departmentId);

            //print("<pre>".print_r($deps, true)."</pre>");

            $helpTopics = array();
            foreach ($topics as $key => $value){

                $top = Topic::Lookup($key);
                $tmp = array(
                    'id' => $key,
                    'name' => $top->getName()
                );

                $topicDeptId = $top->getDeptId();

                /*  if parameter to include parents was true:
                 *          we get through all the parent departments and check if the current topic matches any of them
                 *
                 *  if parameter to include parents was false:
                 *             deps will include only department sent as a parameter and we get only his topics
                 */
                foreach ($deps as $dep){
                    if($topicDeptId == $dep['id']){
                        array_push($helpTopics,$tmp);
                        break;
                    }
                }
            }

            $result = array(
                'help_topics' => $helpTopics,
                'status_code' => '0',
                'status_msg' => 'success'
            );

            $result_code = 200;
            $this->response($result_code, json_encode($result), $contentType = "application/json");

        } catch (Throwable $e) {
            $msg = $e->getMessage();
            $result = array('departments' => array(), 'status_code' => 'FAILURE', 'status_msg' => $msg);
            $this->response(500, json_encode($result),$contentType = "application/json");
        }
    }
}



//Local email piping controller - no API key required!
class PipeApiController extends TicketApiController {

    //Overwrite grandparent's (ApiController) response method.
    function response($code, $resp, $contentType = 'text/plain') {

        //Use postfix exit codes - instead of HTTP
        switch($code) {
            case 201: //Success
                $exitcode = 0;
                break;
            case 400:
                $exitcode = 66;
                break;
            case 401: /* permission denied */
            case 403:
                $exitcode = 77;
                break;
            case 415:
            case 416:
            case 417:
            case 501:
                $exitcode = 65;
                break;
            case 503:
                $exitcode = 69;
                break;
            case 500: //Server error.
            default: //Temp (unknown) failure - retry
                $exitcode = 75;
        }

        //echo "$code ($exitcode):$resp";
        //We're simply exiting - MTA will take care of the rest based on exit code!
        exit($exitcode);
    }

    function  process() {
        $pipe = new PipeApiController();
        if(($ticket=$pipe->processEmail()))
           return $pipe->response(201, $ticket->getNumber());

        return $pipe->exerr(416, __('Request failed - retry again!'));
    }
}

?>
