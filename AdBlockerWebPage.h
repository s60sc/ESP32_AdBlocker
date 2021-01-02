
// ESP32_AdBlocker web page content
const char* index_html = R"~(
<!doctype html>
<html>
  <head>
    <meta http-equiv="Content-Type" content="text/html; charset=utf-8" />
    <title>ESP32_AdBlocker</title>
    <script src="https://ajax.googleapis.com/ajax/libs/jquery/2.1.3/jquery.min.js"></script>
    <STYLE type="text/css">
      body {
        margin: 10px;
      }
    
      table {
        font-family: arial, sans-serif;
        border-collapse: collapse;
        width: 90%;
      }
        
      td, th {
        border: 0px solid #dddddd;
        text-align: left;
        padding: 8px;
      } 
      input[type="text"] {
        padding: 10px; 
        font-size: 16px; 
        width: 90%
      }
      input[type="submit"], input[type="file"] {
        padding: 10px; 
        background-color: #e7e7e7;
        font-size: 16px; 
      }
    </STYLE>
  </head>
  <body>
    </br></br>
    <table><tr>
      <td width=10%><b>Allowed:</b></td><td id="1">Waiting</td>
      </tr><tr>
      <td><b>Blocked:</b></td><td id="2">Waiting</td>
      </td></td>
    </table><br/>
    <table><tr>
      <td width=10%><input type="submit" id="UpdateBtn" value="Update"/></td>
      <td><input type="text" id="3" value="n/a"></td>
      </tr></br></br><tr>
      <td><input type="submit" id="ResetBtn" value="Reset  "/></td></tr>      
    </table><br/>
    <script>
      var baseHost = document.location.origin
      var myUrl = baseHost +"/";
      var refreshRate = 2000; // 2 seconds
      $(function(){refreshPage();}); 
    
      function refreshPage(){ 
        console.log("refreshPage");   
        // periodically refresh page content using received JSON
        var myData = $.ajax({ // send request to app
          url: myUrl+"refresh",           
          dataType : "json", 
          timeout : refreshRate, 
          success: function(data) { // receive response from app
            $.each(data, function(key, val) { 
              // replace each existing value with new value, using key name to match html tag id
              $('#'+key).text(val);
              $('#'+key).val(val);
            });
          }
        });
            
        myData.error(function(xhr, status, errorThrown){ 
          console.log("Failed to get data: " + errorThrown); 
          console.log("Status: " + status);
          console.dir(xhr);
        });
        timeOut = setTimeout('refreshPage()', refreshRate);  // re-request data at refreshRate interval in ms
      }
      function sendUpdates() {    
        // get each input field and obtain id/name and value into array
        var jarray = {};
        $('input').each(function () {
          if ($(this).attr('type') == "text") jarray[$(this).attr('id')] = $(this).val().trim();
          // for radio fields return value of radio button that is selected
          if ($(this).attr('type') == "radio" && $(this).is(":checked")) 
            jarray[$(this).attr('name')] = $('input[name="'+$(this).attr('name')+'"]:checked').val();
          // for checkboxes set return to 1 if checked else 0
          if ($(this).attr('type') == "checkbox")
            jarray[$(this).attr('id')] = $(this).is(":checked") ? "1" : "0";
        });
        
        var myData = $.ajax({
          url : '/update',
          type : 'POST',
          contentType: "application/json",
          data : JSON.stringify(jarray)
        });
        myData.error(function(xhr, status, errorThrown){ 
          handleError(xhr, status, errorThrown);
        });
      }
      $('#UpdateBtn').click(function(){ 
        sendUpdates();
      });    
      $('#ResetBtn').click(function() {
        $.ajax({url: myUrl+"reset"});
      });
    </script>
  </body>
</html>
)~";
