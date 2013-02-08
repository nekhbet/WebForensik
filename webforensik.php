#!/usr/bin/env php

<?php

/*------------------------------------------------------------------\
| webforensik.php v0.18 | Wed Mar 28 22:58:39 CEST 2012             |
| License: GPL v2 (http://www.gnu.org/licenses/gpl-2.0.html)        |
|                                                                   |
| **************************** INSTALL **************************** |
| STEP 1: get the latest version of PHPIDS from https://phpids.org, |
|         move this script to your PHPIDS lib/ directory or adjust  |
|         */ static $phpids_lib_path = './'; /*                     |
| STEP 2: (optional) if you consider using dns lookups (-h),        |
|         you might want to run a local, caching nameserver         |
|         like dnsmasq to increase performance a little bit         |
| STEP 3: run ./webforensik.php access.log                          |
|                                                                   |
| *************************** CONFIGURE *************************** |
| you can define your own Apache-style logline formats, e.g.        |
| 'custom' => '%h %l %u %t \"%r\" %>s %b %{X-Forwarded-For}'        |
| (see http://httpd.apache.org/docs/mod/mod_log_config.html)        |
\------------------------------------------------------------------*/

# define allowed input formats (apache style, feel free to complement)
static $allowed_input_types = array(
  'common'     => '%h %l %u %t \"%r\" %>s %b',
  'combined'   => '%h %l %u %t \"%r\" %>s %b \"%{Referer}i\" \"%{User-Agent}i\"',
  'combinedio' => '%h %l %u %t \"%r\" %>s %b \"%{Referer}i\" \"%{User-Agent}i\ %I %O"',
  'cookie'     => '%h %l %u %t \"%r\" %>s %b \"%{Referer}i\" \"%{User-Agent}i\" \"%{Cookie}i\"',
  'vhost'      => '%v %h %l %u %t \"%r\" %>s %b \"%{Referer}i\" \"%{User-Agent}i\"',
);

# define output types (don't change!)
static $allowed_output_types = array('csv', 'html', 'xml');

# by default, don't try to determine hostnames (see '-h')
$dns_lookup = FALSE;

// ------------------------------------------------------------------ //

# turn off PHP warnings (use own ones instead)
error_reporting(E_ERROR | E_PARSE);

# set the include path properly for PHPIDS
set_include_path(get_include_path().PATH_SEPARATOR.$phpids_lib_path);

# try to include PHPIDS framework
$phpids_requires = array('Init.php', 'Event.php');
foreach($phpids_requires as $val)
{
  $required_file = "$phpids_lib_path/IDS/$val";
  if (file_exists($required_file))
    require_once($required_file);
  else
    die("[!] Please run this programm within lib/ of your PHPIDS
    installation or change variable '\$phpids_lib_path'\n\n");
}

# check if running from the command line
if (!defined("STDIN"))
  die("[!] Please run this programm from the CLI\n\n");

// ------------------------------------------------------------------ //

# remove first element first of argv (scriptname)
array_shift($argv);

# parse command line options and flags
foreach(getopt("i:o:h") as $opt => $value)
{
  ### echo "\n======================= <DEBUG: \$argv $opt -> $value> =======================\n";
  ### print_r($argv);
  ### echo "======================= </DEBUG: \$argv ======================\n";

  switch ($opt)
  {
    case 'i':
      $input_type = $value;
      // check for correct input file type
      if (array_key_exists($input_type, $allowed_input_types) == FALSE)
      {
        echo("[!] Input format '$input_type' not allowed\n");
        usage_die();
      }
      // remove switch and option from argument vector
      if (strlen($argv[0]) <= 2)
        array_shift($argv);
      array_shift($argv);
      break;

    case 'o':
      $output_type = $value;
      // check for correct output file type
      if (in_array($output_type, $allowed_output_types) == FALSE)
      {
        echo("[!] Output format '$output_type' not allowed\n");
        usage_die();
      }
      // remove switch and option from argument vector
      if (strlen($argv[0]) <= 2)
        array_shift($argv);
      array_shift($argv);
      break;

    case 'h':
      echo("[#] Hostname lookup enabled - this might be a significant slowdown\n");
      $dns_lookup = TRUE;
      // we cannot handle two flags at a time
      if (strlen($argv[0]) > 2)
        usage_die();
      // remove flag from argument vector
      array_shift($argv);
      break;
  }
}

# parse command line arguments
if (isset($argv[0]))
  $input_file = $argv[0];
if (isset($argv[1]))
  $output_file = $argv[1];

// ------------------------------------------------------------------ //

# exit, if no input file given
if (!isset($input_file))
{
  echo("[!] Specify at least an input logfile\n");
  usage_die();
}

# try to open input file for reading
if (($input_stream = fopen($input_file, 'r')) == FALSE)
{
  echo("[!] Cannot read from input file '$input_file'\n");
  usage_die();
}

// ------------------------------------------------------------------ //

# try auto-detection of input format, if none given
if (!isset($input_type))
{
  if (($input_type=detect_logformat($input_stream, $allowed_input_types)) == FALSE)
  {
    echo("[!] Cannot auto-detect input format of '$input_file'\n");
    usage_die();
  }
  else
    echo("[#] No input file format given - guessing '$input_type'\n");
}

# set regex for given input format
$regex = format_to_regex($allowed_input_types[$input_type]);
$regex_fields = $regex[0];
$regex_string = $regex[1];
$field_index = count($regex_fields);

// ------------------------------------------------------------------ //

# set default output format, if none given
if (!isset($output_type))
{
  $output_type=$allowed_output_types[0];
  echo("[#] No output file format given - using '$output_type'\n");
}

# set default output filename, if none given
if (!isset($output_file))
{
  $output_file='report_' . date("d-M-Y-His") . '.' . $output_type;
  echo("[#] No output file given - using '$output_file'\n");
}

# try to open output file for writing
if (($output_stream = fopen($output_file, 'w')) == FALSE)
{
  echo("[!] Cannot write to output file '$output_file'\n");
  usage_die();
}

// ------------------------------------------------------------------ //

# set counters for statistics
$attack_index = 0; $vector_index=0; $line_index = 0; $progress = -1;
$tags = array(); $clients = array();

#  count number of lines of input file
$num_lines = count_lines($input_stream, $input_file);

#  insert header data into logfile
log_header($output_stream, $output_type, $regex_fields, $output_file);

// ------------------------------------------------------------------ //

# main program starts here
while ($line = fgets($input_stream))
{
  // increment line index
  $line_index++;

  // remove junk like MS-wordwraps
  $line = trim($line);

  // ignore empty lines
  if (empty($line))
    continue;

  // convert logline to request object
  $data = logline_to_request($line, $regex_string, $regex_fields, $field_index);

  // print error on crippled lines
  if ($data == null)
    print_badline($line, $line_index, $num_lines, $input_type, $input_file);
  else
  {
    // convert http-request to PHPIDS-request
    $request = http_to_phpids($data);

    // pipe request through PHPIDS-filter
    $result = pass_through_phpids($request, $data, $phpids_lib_path);

    if (isset($result))
    {
      // count tags for statistics
      foreach($result->getTags() as $tag)
      {
        // if logline entry contains zero-information, mark aus useless
        $regex_fields = mark_regex_fields_useful($regex_fields, $data);

        // first-time add tag
        if (!(isset($tags[$tag])))
          $tags[$tag] = 1;
        // increment tag index
        else
          $tags[$tag]++;

        /*--------------------------------------\
        | possible tags are (PHPIDS 0.7):       |
        | ************************************* |
        | - 'xss' (cross-site scripting)        |
        | - 'sqli' (sql injection)              |
        | - 'csrf' (cross-site request forgery) |
        | - 'dos' (denial of service)           |
        | - 'dt' (directory traversal)          |
        | - 'spam' (mail header injections)     |
        | - 'id' (information disclosure)       |
        | - 'rfe' (remote file execution)       |
        | - 'lfi' (local file inclusion)        |
        | - 'command execution'                 |
        | - 'format string'                     |
        \--------------------------------------*/

        // increment attack index
        $attack_index++;
      }
      $vector_index++;

      // convert date to unix timestamp format
      if (array_key_exists('Date', $data))
        $data['Date'] = date("r", apachedate_to_timestamp($data['Date']));

      if (array_key_exists('Remote-Host', $data))
      {
        // set client's identity (ip address)
        $client = $data['Remote-Host'];

        // convert ip address to hostname
        if ($dns_lookup == TRUE)
          $data['Remote-Host'] = ipaddr_to_hostname($data['Remote-Host']);

        // first-time add client
        if (!(isset($clients[$client])))
          $clients[$client] = 1;
        // increment client index
        else
          $clients[$client]++;
      }

      // log the incident itself
      log_incident($output_stream, $output_type, $result, $data, $vector_index);
    }

    // do stuff, but only for the very first time
    if ($line_index == 1) 
    {
      // from here on, catch SIGINT (CTRL+C)
      declare(ticks = 1);
      pcntl_signal(SIGINT, "clean_exit");
    }

    // show console progress bar :)
    $progress = progress_bar($line_index, $num_lines, $progress, $input_file);
  }
}

// ------------------------------------------------------------------ //

# insert footer data into logfile
log_footer($output_stream, $output_type, $regex_fields);

# print some statistics
print_statistics($attack_index, $vector_index, count($clients), $tags, $output_file);

# close i/o streams
fclose($input_stream);
fclose($output_stream);

// ------------------------------------------------------------------ //

# function: print usage and exit
function usage_die()
{
  // define those variables global, we have to deal with
  global $allowed_input_types, $allowed_output_types;

  echo("\nUsage: webforensik [-i input_type] [-o output_type]");
  echo("\n                   [-h] input_logfile [output_file]");
  echo("\n\n -i allowed input types:");
  foreach($allowed_input_types as $key => $val)
    echo " $key";
  echo("\n -o allowed output types:");
  foreach($allowed_output_types as $val)
    echo " $val";
  echo("\n -h resolve hostnames");
  die("\n\n");
}

// ------------------------------------------------------------------ //

# function: auto-detect logfile format
function detect_logformat($stream, $allowed_input_types)
{
  // try detection for the first couple of lines
  for ($line_index = 0; $line_index < 10; $line_index++)
  {
    // get next line of logfile and remove junk
    $line = fgets($stream);
    $line = trim($line);
    // try to auto-detect format
    foreach($allowed_input_types as $key => $val)
    {
      $regex = format_to_regex($val);
      $regex_fields = $regex[0];
      $regex_string = $regex[1];
      $field_index = count($regex_fields);
      $data = logline_to_request($line, $regex_string, $regex_fields, $field_index);
      if (isset($data))
        return $key;
    }
  }
  // auto-detection failed
  return null;
}

// ------------------------------------------------------------------ //

# function: convert HTTP-request to PHPIDS-compatible request
function http_to_phpids($data)
{
  ### echo "\n======================= <DEBUG: \$data> =======================\n";
  ### print_r($data);
  ### echo "======================= </DEBUG: \$data> ======================\n";

  if (array_key_exists('Request', $data))
  {
    if (preg_match("/^(\S+) (.*?) HTTP\/[0-9]\.[0-9]\z/", $data['Request'], $match))
    {
      // parse query part of given url
      $url_query = parse_url($match[2], PHP_URL_QUERY);

      // implement 'whitelist' for harmless urls
      $url_harmless = preg_match('!^[\w\!/~#+-.]*$!', $match[2]);

      // use whole url, if query is crippled and non-harmless
      if ($url_query == FALSE and !($url_harmless))
        $url_query = $match[2];

      // convert url query (e.g. foo=bar) into array
      parse_str($url_query, $parameters);

      // normally, PHPIDS would work on an already urldecoded $_REQUEST
      foreach($parameters as &$val)
        $val = urldecode($val);

      ### echo "\n======================= <DEBUG: \$parameters> =======================\n";
      ### echo "parameters: "; print_r($parameters);
      ### echo "======================= </DEBUG: \$parameters> ======================\n";
       
      if (empty($parameters))
        // if nonexistent, don't even pass request to PHPIDS (-> speed boost)
        return null;
      else 
        return array($parameters);
    }
    else
      // make PHPIDS inspect (urldecoded) whole request, if malformed / non-rfc2616
      return array(urldecode($data['Request']));
  }
  else
    // if request nonexitent, we've nothing to inspect
    return null;
}

// ------------------------------------------------------------------ //

# function: pipe request through PHPIDS-filter
function pass_through_phpids($request, $data, $phpids_lib_path)
{
  // check if request exists
  if (!(isset($request)))
    return null;

  try
  {
    // overwrite some configs so we can always find the PHPIDS directory
    $init = IDS_Init::init($phpids_lib_path . '/IDS/Config/Config.ini.php');
    $init->config['General']['base_path'] = $phpids_lib_path . '/IDS/';
    $init->config['General']['use_base_path'] = TRUE;

    // initiate the PHPIDS and fetch/return the results
    $ids = new IDS_Monitor($request, $init);
    $result = $ids->run();

    if (!$result->isEmpty())
    {
      ### echo "\n======================= <DEBUG: \$result> =======================\n";
      ### print_r ($result);
      ### echo "======================= </DEBUG: \$result> ======================\n";

      return $result;
    }
    else
      return null;
  }
  catch (Exception $e)
  {
    // sth went terribly wrong
    printf("\n[!] PHPIDS error occured: %s", $e->getMessage());
    return null;
  }
}

// ------------------------------------------------------------------ //

# function: insert header data into logfile
function log_header($stream, $type, $fields, $file)
{
  switch ($type)
  {
    // - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -//
    case 'csv':
      $logstr = 'Impact;Tags;';
      foreach($fields as $key => $val)
        $logstr .= $key . ';';
      break;
    // - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -//
    case 'html':
      // this is modern times, ppl want stylesheets ;)
      $logstr = '<html><head>
                 <title>Webforensic [' . $file . ']</title>
                 <link rel="stylesheet" type="text/css" href="include/style_table.css" />
                 </style>
                 <script src="include/tablefilter.js"></script>
                 <script src="include/sortable.js"></script>
                 </head>
                 <body>
                 <table id="webforensik" class="sortable">
                 <thead><tr><th>Impact</th><th>Tags</th>';
      foreach($fields as $key => $val)
        $logstr .= '<th>' . $key . '</th>';
      $logstr .= '</tr></thead><tbody>';
      break;
    // - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -//
    case 'xml':
      $logstr = '<?xml version="1.0" encoding="ISO-8859-1"?>';
      $logstr .= '<data title="' . $file . '">';
      break;
  }
  fputs($stream, $logstr . "\n");
}

// ------------------------------------------------------------------ //

# function: insert main data into logfile
function log_incident($stream, $type, $result, $data, $vector_index)
{
  // don't fuck up the reports with 'special characters' (binary)
  // (might especially happen when -u flag is used for urlencode)
  foreach($data as $key => $val)
    $data[$key] = filter_var($val, FILTER_SANITIZE_STRING, FILTER_FLAG_STRIP_LOW);

  switch ($type)
  {
    // - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -//
    case 'csv':
      $logstr = '"' . $result->getImpact() . '";"';
      foreach($result->getTags() as $tag)
        $logstr .= $tag . ' ';
      $logstr .= '";';
      // escape csv-reserved characters
      foreach($data as $key => $val)
        $logstr .= '"' . str_replace('\"', '""', $val) . '";';
      break;
    // - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -//
    case 'html':
      $logstr = '<tr><td>' . $result->getImpact() . '</td><td>';
      foreach($result->getTags() as $tag)
        $logstr .= $tag . ' ';
      $logstr .= '</td>';
      foreach($data as $key => $val)
      {
        // set max size for <td>...</td> content
        $td_limit_break = 4096;
        $td_limit_tooltip = 52;
        // escape html-reserved characters (else we might re-open the payload!)
        $val_filtered = filter_var($val, FILTER_SANITIZE_SPECIAL_CHARS);
        // trim really long lines
        if (strlen($val_filtered) > $td_limit_break)
          $val_filtered = substr($val_filtered, 0 , $td_limit_break);
        // show tooltip for long lines
        if (strlen($val_filtered) > $td_limit_tooltip)
          $logstr .= '<td title="' . $val_filtered . '">' . $val_filtered . '</td>';
        else
          $logstr .= '<td>' . $val_filtered . '</td>';
      }
      $logstr .= '</tr>';
      break;
    // - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -//
    case 'xml':
      $logstr = '<event start="' . $data['Date'] . '" title="' . $data['Remote-Host'] . ' (' . $result->getImpact() . ')">';
      // this makes perfect sense, dont't touch :)
      $logstr .= 'Impact: ' . $result->getImpact() . '&lt;br&gt;Tags: ';
      foreach($result->getTags() as $tag)
        $logstr .= $tag . ' ';
      $logstr .= '&lt;br&gt;';
      foreach($data as $key => $val)
        // escape html-reserved characters (else we might re-open the payload!)
        $logstr .= $key . ': ' . htmlentities(filter_var($val, FILTER_SANITIZE_SPECIAL_CHARS), ENT_QUOTES) . '&lt;br&gt;';
      $logstr .= '</event>';
      break;
  }
  fputs($stream, $logstr . "\n");
}

// ------------------------------------------------------------------ //

# function: insert footer data into logfile
function log_footer($stream, $type, $regex_fields)
{
  switch ($type)
  {
    // - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -//
    case 'csv':
      $logstr = '';
      break;
    // - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -//
    case 'html':
      $logstr = '</tbody></table><script>';
      // leave space for cols 'Impact' and 'Tags'
      $col_index = 2;
      // hide zero-information columns
      $logstr .= 'var useless_cols = new Array(); ';
      foreach($regex_fields as $key => $val)
      {
        if ($val != 'USEFUL')
          $logstr .= 'useless_cols.push("' . $col_index . '"); ';
        $col_index++;
      }
      $logstr .= 'setFilterGrid("webforensik");</script>';
      $logstr .= '</body><html>' . "\n";
      break;
    // - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -//
    case 'xml':
      $logstr = '</data>' . "\n";
      break;
  }
  fputs($stream, $logstr);
}

// ------------------------------------------------------------------ //

# function: count number of lines of file
function count_lines($stream, $file)
{
  // print feedback (important, when dealing with huge files)
  print("[>] Counting number of lines of '$file'");
  $num_lines = 0;
  // reset position indicator to zero
  fseek($stream, 0);
  // loop over input file and count lines
  while (fgets($stream)) 
    $num_lines++;
  // reset position indicator to zero
  fseek($stream, 0);
  // return number of lines
  return $num_lines;
}

// ------------------------------------------------------------------ //

# function: show console progress bar
function progress_bar($line_index, $line_count, $progress, $input_file)
{
  $progress_new = ceil($line_index * 100 / $line_count);
  if ($progress_new != $progress)
    print("\r[>] Processing $line_count lines of input file '$input_file' [$progress_new%]");
  return $progress_new;
}

// ------------------------------------------------------------------ //

# function: print error on crippled lines
function print_badline($line_binary, $line_index, $line_count, $input_type, $input_file)
{
  // don't fuck up the terminal with 'special characters' (binary)
  $line_ascii = preg_replace('/[^(\x20-\x7E)]*/', '', $line_binary);
  printf("\r");
  for ($char = 0; $char <= 45 + strlen($input_file) + strlen($line_count); $char++)
    printf(" ");
  printf("\r[#] Line '%d' crippled or not of type '%s':\n    '%s'\n", $line_index, $input_type, $line_ascii);
}

// ------------------------------------------------------------------ //

# function: print some statistics
function print_statistics($attack_index, $vector_index, $client_count, $tags, $output_file)
{
  echo("\n\n    Found $vector_index incidents ($attack_index tags) from $client_count clients");
  # tag statistics
  $tag_index = 0;
  foreach($tags as $tag => $val)
  {
    // insert newline
    if ($tag_index % 3 == 0)
      echo("\n    | ");
    // print tag and value
    printf("%-9s%8d | ", "$tag:", "$val");
    // increment tag index
    $tag_index++;
  }
  echo("\n\n[>] Check out '$output_file' for a complete report\n\n");
}

// ------------------------------------------------------------------ //

# function: parse apache custom log format into regex
#           credits go to Hamish Morgan's apachelogregex
function format_to_regex($format)
{
  $format = preg_replace(array('/[ \t]+/', '/^ /', '/ $/'), array(' ', '', ''), $format);
  $regex_elements = array();

  foreach(explode(' ', $format) as $element)
  {
    $quotes = preg_match('/^\\\"/', $element) ? TRUE : FALSE;
    if($quotes)
      $element = preg_replace(array('/^\\\"/', '/\\\"$/'), '', $element );

    $regex_fields[formatstr_to_desc($element)] = null;

    if($quotes)
    {
      if ($element == '%r'
      or (preg_match('/{(.*)}/', $element)))
        $x = '\"([^\"\\\\]*(?:\\\\.[^\"\\\\]*)*)\"';
      else
        $x = '\"([^\"]*)\"';
    }
    elseif ( preg_match('/^%.*t$/', $element) )
      $x = '(\[[^\]]+\])';
    else
      $x = '(\S*)';

    $regex_elements[] = $x;
  }

  $regex_string = '/^' . implode(' ', $regex_elements ) . '$/';
  $regex = array($regex_fields, $regex_string);

  ### echo "\n======================= <DEBUG: \$regex> =======================\n";
  ### print_r($regex);
  ### echo "======================= </DEBUG: \$regex> ======================\n";

  return $regex;
}

// ------------------------------------------------------------------ //

# function: parse logline into http-request array
function logline_to_request($line, $regex_string, $regex_fields, $num_fields)
{
  // line cannot be parsed for some reason
  if (preg_match($regex_string, $line, $matches) !== 1)
    return null;
  // create http-request array
  reset($regex_fields);
  for ($n = 0; $n < $num_fields; ++$n)
  {
    $field = each($regex_fields);
    $out[$field['key']] = $matches[$n + 1];
  }
  return $out;
}

// ------------------------------------------------------------------ //

# function: convert apache format strings to description
#           credits go to Hamish Morgan's apachelogregex
function formatstr_to_desc($field)
{
  static $orig_val_default = array('s', 'U', 'T', 'D', 'r');
  static $trans_names = array(
    '%' => '',
    'a' => 'Remote-IP',
    'A' => 'Local-IP',
    'B' => 'Bytes-Sent-X',
    'b' => 'Bytes-Sent',
    'c' => 'Connection-Status', // <= 1.3
    'C' => 'Cookie', // >= 2.0
    'D' => 'Time-Taken-MS',
    'e' => 'Env-Var',
    'f' => 'Filename',
    'h' => 'Remote-Host',
    'H' => 'Request-Protocol',
    'i' => 'Request-Header',
    'I' => 'Bytes-Received', // requires mod_logio
    'l' => 'Remote-Logname',
    'm' => 'Request-Method',
    'n' => 'Note',
    'o' => 'Reply-Header',
    'O' => 'Bytes-Sent', // requires mod_logio
    'p' => 'Port',
    'P' => 'Process-Id', // {format} >= 2.0
    'q' => 'Query-String',
    'r' => 'Request',
    's' => 'Status',
    't' => 'Date',
    'T' => 'Time-Taken-S',
    'u' => 'Remote-User',
    'U' => 'Request-Path',
    'v' => 'Server-Name',
    'V' => 'Server-Name-X',
    'X' => 'Connection-Status', // >= 2.0
    );

    foreach($trans_names as $find => $name)
    {
      if(preg_match("/^%([!\d,]+)*([<>])?(?:\\{([^\\}]*)\\})?$find$/", $field, $matches))
      {
        if (!empty($matches[2]) and $matches[2] === '<' and !in_array($find, $orig_val_default, TRUE))
          $chooser = "Original-";
        elseif (!empty($matches[2]) and $matches[2] === '>' and in_array($find, $orig_val_default, TRUE))
          $chooser = "Final-";
        else
          $chooser = '';
        $name = "{$chooser}" . (!empty($matches[3]) ? "$matches[3]" : $name) . (!empty($matches[1]) ? "($matches[1])" : '');
        break;
      }
    }
    if(empty($name))
      return $field;

    // returns original name if there is a problem
    return $name;
}

// ------------------------------------------------------------------ //

# function: convert 'standard english format' to unix timestamp
function apachedate_to_timestamp($time)
{
  list($d, $M, $y, $h, $m, $s, $z) = sscanf($time, "[%2d/%3s/%4d:%2d:%2d:%2d %5s]");
  return strtotime("$d $M $y $h:$m:$s $z");
}

// ------------------------------------------------------------------ //

# function: if logline entry contains zero-information, mark aus useless
  function mark_regex_fields_useful($regex_fields, $data)
{
  foreach ($data as $key => $val)
    if (!(($val == '-')))
      $regex_fields[$key] = 'USEFUL';
  return $regex_fields;
}

// ------------------------------------------------------------------ //

# function: convert ip address to hostname, if possible
function ipaddr_to_hostname($ipaddr)
{
  // return argument, if it already contains a hostname
  if (preg_match("/^.*[a-zA-Z]$/", $ipaddr))
    return $ipaddr;

  // convert ip address to reverse IN-ADDR entry
  $reverse_ipaddr = implode('.', array_reverse(explode('.', $ipaddr))) . '.in-addr.arpa';
  // lookup PTR-record, but faster than gethostbyaddr()
  $record = dns_get_record($reverse_ipaddr, DNS_PTR);
  // check if ip address resolved to hostname
  if (isset($record[0]['target']))
    $hostname = $record[0]['target'];
  // if not, return ip address
  else
    $hostname = $ipaddr;

  ### echo "\n======================= <DEBUG: \$ipaddr> =======================\n";
  ### echo "ipaddr: $ipaddr | hostname: $hostname\n";
  ### echo "======================= </DEBUG: \$ipaddr> ======================\n";

  return $hostname;
}

// ------------------------------------------------------------------ //

# function: do a clean exit when reveiving SIGINT
function clean_exit()
{
  // define those variables global, we have to deal with
  global $output_file, $output_stream, $output_type, $regex_fields,
         $dns_lookup, $attack_index, $vector_index, $clients, $tags;
  echo("\n[!] SIGINT received - writing report and exiting");
  log_footer($output_stream, $output_type, $regex_fields, $dns_lookup);
  print_statistics($attack_index, $vector_index, count($clients), $tags, $output_file);
  exit();
}

?>
