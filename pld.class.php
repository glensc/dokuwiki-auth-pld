<?php
/**
 * Plaintext authentication backend for PLD Linux
 *
 * @license    GPL 2 (http://www.gnu.org/licenses/gpl.html)
 * @author     Elan Ruusamäe <glen@pld-linux.org>
 */

// copied from CVSROOT/passwd
define('AUTH_USERFILE', DOKU_CONF.'/pld/passwd');
// cvs up CVSROOT/users
define('AUTH_INFOFILE', DOKU_CONF.'/pld/users');
// manually modified
define('AUTH_GROUPFILE', DOKU_CONF.'/pld/groups');

require_once 'plain.class.php';

class auth_pld extends auth_plain {
    /**
     * Constructor
     *
     * Carry out sanity checks to ensure the object is
     * able to operate. Set capabilities.
     *
     */
    function __construct() {
        if (!@is_readable(AUTH_USERFILE)){
            $this->success = false;
        }else{
            $this->cando['getUsers']     = true;
            $this->cando['getUserCount'] = true;
        }
    }
    /**
     * Return user info
     *
     * Returns info about the given user needs to contain
     * at least these fields:
     *
     * name string  full name of the user
     * mail string  email addres of the user
     * grps array   list of groups the user is in
     *
     */
    function getUserData($user){
        if ($this->users === null) {
            $this->_loadUserFile();
        }

        return isset($this->users[$user]) ? $this->users[$user] : false;
    }

    /**
     * Load all user data
     *
     * loads the user file into a datastructure
     *
     */
    private function _loadUserFile(){
        $this->users = array();

        if(!@file_exists(AUTH_USERFILE)) return;

        $lines = file(AUTH_USERFILE);
        foreach($lines as $line){
            $line = preg_replace('/#.*$/','',$line); //ignore comments
            $line = trim($line);
            if(empty($line)) continue;

            $row = explode(":",$line,6);

            // skip builders
            if (preg_match('/^builder/', $row[0])) {
                continue;
            }

            // skip if fifth column is set is not 'Enable'
            if (!empty($row[5]) && $row[5] != 'Enable') {
                continue;
            }

            // translate group 'cvs' to 'user'
            $groups = str_replace("cvs", "user", $row[2]);
            $groups = array_unique(array_filter(explode(".", $groups)));

            $this->users[$row[0]]['pass'] = $row[1];
            $this->users[$row[0]]['name'] = urldecode($row[4]);
            $this->users[$row[0]]['mail'] = $row[0].'@pld-linux.org';
            $this->users[$row[0]]['grps'] = $groups;
        }

        $this->_loadGroupFile();
        $this->_loadInfoFile();
    }

    /**
     * load additional groups for users
     */
    private function _loadGroupFile() {
      if(!@file_exists(AUTH_GROUPFILE)) return;

      $lines = file(AUTH_GROUPFILE);
      foreach($lines as $line){
        $line = preg_replace('/#.*$/','',$line); //ignore comments
        $line = trim($line);
        if (empty($line)) continue;

        $row = explode(":", $line, 2);
        $user = array_shift($row);
        $groups = explode(",",$row[0]);

        if (!isset($this->users[$user])) {
            continue;
        }

        $groups = array_merge($this->users[$user]['grps'], $groups);

        // remove users with @readonly group from 'users'
        if (array_search('readonly', $groups)) {
            $groups = array_filter($groups, function($v) { return $v != 'user'; });
        }

        $this->users[$user]['grps'] = $groups;
      }
    }

   /**
    * load users file, name and optional jid
    */
   private function _loadInfoFile() {
      if(!@file_exists(AUTH_INFOFILE)) return;

      $lines = file(AUTH_INFOFILE);
      foreach($lines as $line){
        $line = preg_replace('/#.*$/','',$line); //ignore comments
        $line = trim($line);
        if (empty($line)) continue;

        list($user, $mail, $name, $jid) = explode(":", $line, 4);

        if (!isset($this->users[$user])) {
            continue;
        }
        if (!empty($name)) {
            $this->users[$user]['name'] = $name;
        }
        if (!empty($jid)) {
            $this->users[$user]['jid'] = $jid;
        }
      }
    }

    function useSessionCache($user){
        // our backend is fast (all files are local). do not cache
        return false;
    }
}
//Setup VIM: ex: et ts=2 :
