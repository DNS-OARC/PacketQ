$(function() {
	
	/*
	--------------------------------------------------
	DIALOG CREATION BELOW
	--------------------------------------------------
	*/
	
	//Set X positon of dialog
	var dialog_position_x = 10;
	
	//Functions for create menu object
	function create_menu_object(id, name, disable, autoopen, modal, position_x, position_y) {
		//Create the button to the menu
		$("#toolbar").append(" <input type=\"checkbox\" id=\"button_"+id+"\" /><label for=\"button_"+id+"\">"+name+"</label> ");
		$("#button_"+id).button();
		
		//Disable the buttun if its set to true
		if(disable==true) $("#button_"+id).button("disable");
		
		//Create the div that we will write to
		$("<div id=\""+id+"\" class=\"tal\" style=\"overflow:hidden;\"></div>").appendTo("body");
		
		//Set the position of the dialog
		if(position_x == undefined) { position_x = dialog_position_x; dialog_position_x += 310; }
		if(position_y == undefined) position_y = 100;
		if(modal != true) { modal = false; } else { position_y = 'center'; position_x = 'center'; }
		
		//Option for the dialog box
		$( "#"+id ).dialog({
			autoOpen: false,
			position: [position_x, position_y],
			title: name,
			minHeight: 0,
			modal: modal
		});
		
		//Open/close menu item if selected/deselected but NOT for the run question button
		if(id!="run_question") {
			$("#button_"+id).click(function () { 
				if($( "#"+id ).dialog( "isOpen" )==false) {
					$( "#"+id ).dialog( "open" );
				} else {
					$( "#"+id ).dialog( "close" );
				}
			});
		}
		
		//Deselect menu item if dialog closed
		$( "#"+id ).bind( "dialogclose", function(event, ui) {
			$('input[id=button_'+id+']').attr('checked', false);
			$("#button_"+id).button("refresh");
		});
		
		//If auto open is true then open the dialog
		if(autoopen==true) {
			$( "#"+id ).dialog( "open" );
			$('input[id=button_'+id+']').attr('checked', true);
			$("#button_"+id).button("refresh");
		}
		
		
	}
	
	//Call function for create menu item and objects
	create_menu_object('server_list', 'Server list', false, true);
	create_menu_object('questionTree', 'Queries', false, true);
	create_menu_object('fileTree', 'Files', false, true);
	create_menu_object('custom_query', 'Custom Query', true, false, true);
	create_menu_object('detailed_question', 'Detailed Question', true, false, true);
	create_menu_object('files_in_folder', 'Filegraph', false, true, false, 10, 400);
	create_menu_object('run_question', 'Run question', true);
	
	
	/*
	--------------------------------------------------
	FILE LOAD BELOW
	--------------------------------------------------
	*/
	var apiPath = "/";
	var Questions;
	var encode_url = 0;
	var hiddenQuestions;
	var alert_load_time = 0;
	
	//Load config file
	$.getJSON('_config.json', function(data) {
		var items = [];
		Config = data;
		alert_load_time = Config[0].alert_load_time;
	});
	
	//Load question file
	$.getJSON('_questions.json', function(data) {
		var items = [];
		Questions = data;
	});
	
	//Load hidden question file
	$.getJSON('_questions_hidden.json', function(data) {
		var items = [];
		hiddenQuestions = data;
	});
	
	//Load server file
	$.getJSON('_servers.json.php', function(data) {
		var items = [];
		var theServers = data;
		apiPath = theServers[0].url;
		encode_url = theServers[0].encode_url;

		//Update server dialog
		get_servers(apiPath, theServers);
	});
	
	/*
	--------------------------------------------------
	CREATE AND UPDATE SERVER LIST BELOW
	--------------------------------------------------
	*/
	
	//Write servers to its dialog
	function get_servers(apiPath, theServers) {
		var change_server = 0;

		for(var i=0; i<theServers.length; i++) {

			//For active server
			if(apiPath==theServers[i].url&&active_server == undefined) {
				$("#server_list").append("<p class=\"server_title\"><b>Active server</b></p>");
				$("#server_list").append("<p>"+theServers[i].name+"</p>");
				var active_server = i;
				i = -1;
				create_fileTree(apiPath);
			} 
			//For inactive servers
			else if(active_server != undefined && i!= active_server) {
				if(change_server==0) $("#server_list").append("<p class=\"server_title mt10\"><b>Change server</b></p>");
				$("#server_list").append("<p class=\"cp\" id=\"serverid"+i+"\">"+theServers[i].name+"</p>");
				
				change_active_server(i, theServers);
				
				change_server++;
			}
			
		}
	}
	
	//Function for what will happen when new server is active
	function change_active_server(i, theServers) {
		$("#serverid"+i).click(function() {
			//Empty server dialog
			$("#server_list").empty();
			
			//Update server dialog
			get_servers(theServers[i].url, theServers);
		});
	}

	/*
	--------------------------------------------------
	CREATE QUESTION TREE BELOW
	--------------------------------------------------
	*/

	//Write question tree to its dialog
	$("#questionTree").jstree({
	
		"themes" : {
			"theme" : "dotse",
			"dots" : false,
			"icons" : false
		},
		"ui" : {
			"select_limit" : 1
		},
		"json_data" : {
			"ajax" : {
				"url" : "_questions.json",
				"data" : function (n) {
					return { id : n.attr ? n.attr("id") : 0 };
				}
			}
		},
		"plugins" : [ "themes", "json_data", "ui"],
	});
	
	//Create variable to show all on default
	var currentFiletype = 'show_all'
	
	//Do when selected node
	$("#questionTree").bind('select_node.jstree', function(event, data) {

		var question = $("#questionTree").jstree("get_selected");
		
		if(question.attr('filetype') != 'folder' && question.attr('filetype')!='show_all'){
		//Not cliking a folder	
			if (currentFiletype != question.attr('filetype')){

				currentFiletype = question.attr('filetype');
				
				//Filter list on filetype
				$("#fileTree").jstree("get_container").find("li").andSelf().each(function () {
					if(this.type!=currentFiletype&&this.type!="") $("li[id*='"+this.id+"']").hide();
					if(this.type==currentFiletype) $("li[id*='"+this.id+"']").show();
				});

			}
		}
		
		//If show all, then do that
		if(question.attr('filetype')=='show_all') {
			
			$("#fileTree").jstree("get_container").find("li").andSelf().each(function () {
				$("li[id*='"+this.id+"']").show();
			});
		}
		
		//Run the run question function
		enable_run_question();
		
	});
	
	
	/*
	--------------------------------------------------
	CREATE FILE LIST BELOW
	--------------------------------------------------
	*/
	
	function create_fileTree(apiPath) {
		$("#fileTree").jstree({
			"themes" : {
				"theme" : "dotse",
				"dots" : false,
				"icons" : false
			}, 
			rules : {
				deletable : "all"
			},
			"json_data" : {
				"ajax" : {
					"url" : function (n) { 
						return  n.attr ? apiPath+"list"+n.attr("id") : apiPath+"list" ; 
					},
				},
			},
			"plugins" : [ "themes", "json_data", "checkbox", "ui", "sort" ],
		
		});
		
		//Set so max height of file list is 500
		$("#fileTree").css({"overflow-y" : "scroll", "max-height" : "500px"});
		
		//Create the refresh button to file list
		$("#fileTree").bind("loaded.jstree", function (event, data) {
			$("#fileTree").append("<p class=\"tac\"><button id=\"reload_filetree_button\">Reload</button></p>");
			$("#reload_filetree_button" ).click(function() { $("#fileTree").jstree("refresh"); });
			$("#reload_filetree_button").button();
		});
		
		//If any changes in the file list do this jensa
		$("#fileTree").bind("change_state.jstree", function (e, data) {
			//Get checked files
			var checked_files = $("#fileTree .jstree-checked");
			//Loop through selected files
			$(checked_files).each(function(index) {
				var this_folder = $(this);
				//Open checked node
				$("#fileTree").jstree("open_node", this_folder,
				function () {
					
					//Run the files in folder function
					get_overview_diagram();	
					//Run the run question function
					enable_run_question();
					
					//Close node again
					$("#fileTree").jstree("close_node", this_folder, true);
					
				}
				,true);

			});
			
		});
		
	}
	
	//Change the width of the fileTree window
	$( "#fileTree" ).dialog( "option", "width", 425 );
	
	/*
	--------------------------------------------------
	CREATE CUSTOM FIELD BELOW
	--------------------------------------------------
	*/
	
	//Add the input field to the dialog
	$("#custom_query").append("<p class=\"floatleft mt2\"><input type=\"text\" class=\"f1 w150\" id=\"custom_question_field\" /></p><p class=\"floatright\"><button id=\"run_custom_question\">Run question</button></p>");
	//Create a UI button of Run Question
	$("#run_custom_question").button();
	
	//When we hit the run question button
	$("#run_custom_question").click(function() {
		run_modal_question();
	});
	
	//Deselect run button when we close the dialog and empty field
	$( "#custom_query" ).bind( "dialogclose", function(event, ui) {
		$('input[id=button_run_question]').attr('checked', false);
		$("#button_run_question").button("refresh");
		$("#custom_question_field").val("");	
	});
	
	
	/*
	--------------------------------------------------
	CREATE DETAILED QUESTION FIELD BELOW
	--------------------------------------------------
	*/
	
	//Add the input field to the dialog
	$("#detailed_question").append("<p class=\"floatleft mt2\"><input type=\"text\" class=\"f1 w150\" id=\"detailed_question_field\" /></p><p class=\"floatright\"><button id=\"run_detailed_question\">Run question</button></p>");
	//Create a UI button of Run Question
	$("#run_detailed_question").button();
	
	//When we hit the run question button
	$("#run_detailed_question").click(function() {
		run_modal_question();
	});
	
	//Deselect run button when we close the dialog and empty field
	$( "#detailed_question" ).bind( "dialogclose", function(event, ui) {
			$('input[id=button_run_question]').attr('checked', false);
			$("#button_run_question").button("refresh");	
			$("#detailed_question_field").val("");
	});
	
	/*
	--------------------------------------------------
	FILES IN FOLDER BELOW
	--------------------------------------------------
	*/	
	//Function for the file in folder diagram and enable/disable button
	function get_overview_diagram() {
		
		var checked_files = $("#fileTree .jstree-leaf.jstree-checked");
		
		//Function for disable / enable files in folder
		//if(checked_files.length==0) $("#button_files_in_folder").button("disable");
		//if(checked_files.length>0) {
			
			//Change the size and position of the dialog
			$( "#files_in_folder" ).dialog( "option", "width", 610 );
			$( "#files_in_folder" ).dialog( "option", "height", 245 );
			//$( "#files_in_folder" ).dialog({ position: 'center' });
			
			$("#button_files_in_folder").button("enable");
			
			//Creat the graph
			var chart_overview; // globally available
			$(document).ready(function() {
				chart_overview = new Highcharts.Chart({
					chart: {
						renderTo: 'files_in_folder',
						defaultSeriesType: 'line',
						width: 590,
						height: 205
					},
					
					title: {
						text: 'Filegraph'
					},
					
					yAxis: {
						title: {
							text: 'no',
							style: { display: 'none' }
						}
					},
					
					legend: {
							enabled:false
					},
					tooltip: {
						formatter: function() {
							return this.point.name;
						}
					}
				});
			});
			
			//Create some variables and arrays that we need
			var checked_files_in_folder;
			var re;
			var file_overview = new Array();
			
			//Get the checked files
			checked_files_in_folder = $("#fileTree .jstree-leaf.jstree-checked");
			
				//Store the data into a new array
				var overview_xdata = new Array();
				for(var i=0; i<Config[0].serie.length; i++) {
					
					var z = 0;
					var l = 0;
					
					$(checked_files_in_folder).each(function(index) {
		
						re = new RegExp(Config[0].serie[i].file_prefix);
						if (checked_files_in_folder[z].id.match(re)) {
						
							var datum = new Date( $( this ).attr('time') * 1000);
							var PolledTime = datum.toGMTString();
							var CommaPos = PolledTime.indexOf(',');
	
							file_overview[l] = new Object();
							file_overview[l].y = parseFloat($( this ).attr('size'));
							file_overview[l].name = '<b>'+PolledTime.substring(CommaPos+2, PolledTime.length)+'</b><br />'+checked_files_in_folder[z].id;
							
							l++;
						}
						
						z++;
						
					});
					
					//Add serie and add data to it
					chart_overview.addSeries({
						data: file_overview   
					});
					
					//At last we redraw the graph with the new data
					chart_overview.redraw();
				
				}
		//Function for disable / enable files in folder END!
		//}
		
		//Change chart size if dialog is changed
		$("#files_in_folder").dialog({
			resizeStop: function(event, ui) {
				var divheight=$("#files_in_folder").dialog( "option", "height" )-50;
				var divwidth=$("#files_in_folder").dialog( "option", "width" )-30;
				chart_overview.setSize(divwidth, divheight);
			}
		});
		
	}
	
	/*
	--------------------------------------------------
	RUN QUESTION BELOW
	--------------------------------------------------
	*/
	//Create the load constant outside the function
	var LoadConstant = 8000;
	
	//Enable button variable
	var enable_button_run_question = false;
	
	//Function for enable the run button
	function enable_run_question() {
		var checked_files = $("#fileTree .jstree-leaf.jstree-checked");
		var question = $("#questionTree").jstree("get_selected");
		
		//If both question and file are correct
		if(checked_files.length>0&&question.attr('filetype')!='folder'&&question.attr('filetype')!=undefined) { 

			//Enable run button
			$("#button_run_question").button("enable");
			enable_button_run_question = true;
			
		} else {
			
			//Disable run button
			$("#button_run_question").button("disable");
			enable_button_run_question = false;
		}
	}
	
	//What will happen if click on run question
	$("#button_run_question").click(function () {
		execute_run_queston($("#questionTree").jstree("get_selected"));
	});
	
	//If we hit enter then run question if the run button is enable, empty and close modal windows
	$(window).keypress(function(e) {
		if(e.keyCode == 13) {
			if(enable_button_run_question==true) $("#button_run_question").trigger('click');
			run_modal_question(1);
		}
	});
	
	
	/*
	--------------------------------------------------
	RUN QUESTION FUNCTION BELOW
	--------------------------------------------------
	*/
	function run_question_function(question, modal_question, FileNames, TotalFileSize) {

		var temp_rub = "";
		//Check if input queries modal dialog should be open
		if( question.attr('myid').substr(0, 9)=="detailed_" && modal_question!=1 && question.attr('disable_modal')!=1 && $("#detailed_question_field").attr("value") == "" ) {
			$("#detailed_question").dialog( "open" );
			return false;
		}
		//Check if cusytom question modal dialog should be open
		if( question.attr('myid').substr(0, 2)=="CQ" && modal_question!=1 && $("#custom_question_field").attr("value") == "" ) {
			$("#custom_query").dialog( "open" );
			return false;
		}
		
		//Make sure its not selected beacuse we might want run more then just one question
		$('input[id=button_run_question]').attr('checked', false);
		$("#button_run_question").button("refresh");
		
		//Timestamp that will make this session unique
		var ts = new Date().getTime();
			
		//Creat a variable for the question
		//Check if it is a custom question
		if(question.attr('myid').substr(0, 2) == "CQ") {
			var thisQuestionUrl = $("#custom_question_field").attr("value");
		} 
		//Check if its a detailed question
		else if(question.attr('myid').substr(0, 9) == "detailed_") {
			var thisQuestionUrl = question.attr('myQuestionUrl').replace("$1", $("#detailed_question_field").attr("value"));
			temp_rub = $("#detailed_question_field").attr("value");
		}
		//If none above, take the selected question from tree
		else {
			var thisQuestionUrl = question.attr('myQuestionUrl');
		}
		
		//Make url encode if its defined in server
		var mySource = "query?" + FileNames + 'sql=' + thisQuestionUrl
		if(encode_url==1) mySource = urlencode(mySource);
		
		//Make the JSON call
		var currentSource = apiPath + mySource;
		
		//BEFORE $.post to $.getJSON AND data to json
		$.post( currentSource, { file: FileNames, sql: thisQuestionUrl } , function (data) {
			
			//Calculate the time for the asked question
			var LoadTime = parseInt( new Date().getTime()) - parseInt(ts);

			//Check if the load constant is set larger then default
			if(LoadConstant < (TotalFileSize/LoadTime)) LoadConstant = TotalFileSize/LoadTime;
			
			//Set bar to 100% and stop refresh when data is loaded
			$( "#progressbar_"+ts ).progressbar({ value: 100 });
			clearInterval(auto_refresh);
			
			//When loaded, fadeout bar and show ressult
			$("#progressbar_"+ts).fadeOut(0, function () {
				//Empty the content div
				$("#question_dialog_"+ts).empty();
				
				//Print to the content div if diagram
				if(question.attr('type') == "chart") diagram_question(data, question, ts);
				//Print to the content div if table
				if(question.attr('type') == "table") table_question(data, question, ts);
				
			});
			
		}, "json")
		//If JSON call returns error
		.error(function() {
			//Remove the progressbar and write to div that an error accord
			$( "#progressbar_"+ts ).progressbar({ value: 100 });
			clearInterval(auto_refresh);
			$("#progressbar_"+ts).fadeOut(1600, function () {
				
				//Empty the content div
				$("#question_dialog_"+ts).empty();
				
				//Write to div that an error accord
				$("<p><b>An error accord.</b><br />- No data was returned.</p>").appendTo("#question_dialog_"+ts);
				
			});
		});		
		
		//Create the div that we will write to
		$("<div id=\"question_dialog_"+ts+"\" class=\"tal\" style=\"overflow:hidden;\"><div id=\"progressbar_"+ts+"\"></div></div>").appendTo("body");
		
		//Set title for dialog
		if(temp_rub=="") { var dialog_title = question.text(); } else { var dialog_title = question.text()+" - "+temp_rub; }
		
		//Option for the dialog box
		$( "#question_dialog_"+ts ).dialog({
			autoOpen: true,
			position: 'center',
			title: dialog_title,
			width: 700,
			height: 440
		});

		//Create progress bar that that will be shown before results
		$( "#progressbar_"+ts ).progressbar({ value: 0 });
		
		//Calculate what 1% should be if we update every 0.1 secound
		var j = (TotalFileSize/LoadConstant)/100;
		
		j = 100/j;
		
		var i = 0;
		
		//Refresh progressbar
		var auto_refresh = setInterval(
		function () {
			$( "#progressbar_"+ts ).progressbar({ value: i });
			i += j;

			//Stop update bar if it is completed but the ressult is not loaded yet
			$( "#progressbar_"+ts ).progressbar({
				complete: function(event, ui) { 
					clearInterval(auto_refresh);
				}
			});
		}, 100);
		
		
	}
	
	
	/*
	--------------------------------------------------
	DIAGRAM QUESTIONS BELOW
	--------------------------------------------------
	*/
	function diagram_question(json, question, ts) {
		
		//Create a variable what content is div name
		var diagram_div = "question_dialog_"+ts;
		
		//Creat the graph
		var chart; // globally available
		$(document).ready(function() {
			chart = new Highcharts.Chart({
				chart: {
					renderTo: diagram_div,
					defaultSeriesType: 'line',
					width: 680,
					height: 400
				},
				
				title: {
					text: question.text()
				},
				
				xAxis: {
					labels: {
						enabled : false
					}
				},
				
				yAxis: {
					title: {
						text: 'no',
						style: { display: 'none' }
					},
					labels: {
						enabled : false
					},
					maxPadding: 0,
					minPadding: 0
				},
				
				legend: {
						enabled:false
				},
				tooltip: {
					formatter: function() {
						return this.point.name;
					}
				}
			});
		});

		//Get the right question variable
		for(var i=0; i<Questions.length; i++) {
			for(var j=0; j<Questions[i].children.length; j++) {
				if(Questions[i].children[j].attr.myid==question.attr('myid')) {
					var questionID=i;
					var questionattr=j;
				}
			}
		}
		
		
		var k;
		
		//Check so get_diagram is set in the _question.json file
		if(Questions[questionID].children[questionattr].attr.get_diagram!=""&&Questions[questionID].children[questionattr].attr.get_diagram!=undefined) {
			//Calculate how many series we are about to create
			for(var i=0; i<Questions[questionID].children[questionattr].attr.get_diagram.length; i++) {	
				k = -1;
				
				//Make sure we get the data that we want
				for(var m=0; m<json.head.length; m++) {
					if(Questions[questionID].children[questionattr].attr.get_diagram[i].name==json.head[m].name) { k = m; }
				}
				
				//If not found, just continue
				if(k==-1) continue;
				
				//Set data for the series
				var chart_data = new Array();
				for(var l=0; l<json.data.length; l++) {
					chart_data[l] = new Object();
					chart_data[l].y = json.data[l][k];
					chart_data[l].name = json.data[l][k]+"<br />"+json.head[k].name;
				}
				
				//Add serie and add data to it
				chart.addSeries({
					data: chart_data,
					type: Questions[questionID].children[questionattr].attr.get_diagram[i].type
				});
				
			}
		}
		
		//If we did not write out any lines abow then write all that the file content
		if(chart_data==undefined) {
			for(var i=0; i<json.head.length; i++) {	
				//Set data for the series
				var chart_data = new Array();
				for(var l=0; l<json.data.length; l++) {
					chart_data[l] = new Object();
					chart_data[l].y = json.data[l][i];
					chart_data[l].name = json.data[l][i]+"<br />"+json.head[i].name;
				}
				
				//Add serie and add data to it
				chart.addSeries({
					data: chart_data
				});
			}
		}
		
		
		//Change chart size if dialog is changed
		$("#"+diagram_div).dialog({
			resizeStop: function(event, ui) {
				var divheight=$("#"+diagram_div).dialog( "option", "height" )-50;
				var divwidth=$("#"+diagram_div).dialog( "option", "width" )-30;
				chart.setSize(divwidth, divheight);
			}
		});
		
		
	}
	
	/*
	--------------------------------------------------
	TABLE QUESTIONS BELOW
	--------------------------------------------------
	*/
	var oTable = new Array();
	
	function table_question(json, question, ts) {
		var columns = 0;
		var table_sort = 0;
		var table_sort_type = 'asc';
		
		//Get the right question variable
		for(var i=0; i<Questions.length; i++) {
			for(var j=0; j<Questions[i].children.length; j++) {
				if(Questions[i].children[j].attr.myid==question.attr('myid')) {
					var questionID=i;
					var questionattr=j;
				}
			}
		}
		
		//If sort type is define then set it
		if(question.attr('sort_type')!=undefined) table_sort_type = question.attr('sort_type');
		
		//Write our table and the tables titles		
		var table = "<table id=\"table_"+ts+"\" class=\"table_question\"><thead><tr>";
		for (var i = 0; i < json.head.length; i++) {
			table += "<th><b>"+json.head[i].name;
			
			//If row content is clickable then write it
			for(var k=0; k<Questions[questionID].children[questionattr].attr.link_Array.length; k++) {
				if(Questions[questionID].children[questionattr].attr.link_Array[k].name==json.head[i].name) table += " - Clickable";
			}			
			
			table += "</b></th>";
			//If sort is define then set it
			if(question.attr('sort')!=undefined&&question.attr('sort')==json.head[i].name) table_sort = i;
		}
		table += "</tr></thead>";
		
		//Send the data to the table
		table += "<tbody>";
		for(var j=0; j < json.data.length; j++) {
			table += "<tr>";
			for(var k=0; k<i; k++) {
				table += "<td id=\"t"+k+"_v"+columns+"\"><p style=\"height:15px; overflow:hidden;\"><span>"+json.data[j][k]+"</span><span></span><span></span></p></td>";
				columns++;
			}
			table += "</tr>";
		}
		table += "</tbody>";
		
		//Close the table
		table += "</table>";

		//Add the table to the div
		$(table).appendTo("#question_dialog_"+ts);
		
		//Convert it to a dataTable		
		oTable[ts] = $("#table_"+ts).dataTable({
			'oLanguage': {	'sLengthMenu': '' },
			"sPaginationType": "full_numbers",
			"iDisplayLength": 16,
			"aaSorting": [[table_sort,table_sort_type]]
		});
		
		//Change rows if we change the dialog size
		$("#question_dialog_"+ts).dialog({
			resizeStop: function(event, ui) {
				//Calculate the rows
				var rows = ($('#question_dialog_'+ts).dialog( "option", "height" )-136)/19;
				rows = Math.floor(rows);

				//Redraw the table with new max row
				var oSettings = oTable[ts].fnSettings();
				oSettings._iDisplayLength = (rows);
				oTable[ts].fnDraw();
			}
		});
		
		//What will happend if we click on a row
		$("#table_"+ts+ " td").live("click", function(e) {	
			//Get title column
			var link_Array = $(this).attr("id").split("_");
			var table_position_number = parseInt(link_Array[0].replace("t", ""));
			
			//Check if the field have any hidden questions
			for(var i=0; i<Questions[questionID].children[questionattr].attr.link_Array.length; i++) {
				if(json.head[table_position_number].name==Questions[questionID].children[questionattr].attr.link_Array[i].name) {
					
					//Look for the right hidden question
					for (var j = 0; j < Questions.length; j++) {
						if(Questions[j].attr.id=="HQ") {
							
							for(var k = 0; k < Questions[j].children.length; k++) {
								//If we find a hidden question that match with the column question then run it
								if(Questions[j].children[k].attr.myid==Questions[questionID].children[questionattr].attr.link_Array[i].question) {
									
									//Create a paragraph so we can get value from attr like jstree
									var question_string = Questions[j].children[k];
									$("<p id=\"HQ_paragraph\">"+question_string.data.title+" - "+$(this).text()+"</p>").appendTo("body");
									
									//Add the attr that we need
									$("#HQ_paragraph").attr("myQuestionUrl", question_string.attr.myQuestionUrl.replace("$1", $(this).find("span:eq(0)").text()));
									$("#HQ_paragraph").attr("myid", question_string.attr.myid);
									$("#HQ_paragraph").attr("type", question_string.attr.type);
									$("#HQ_paragraph").attr("sort", question_string.attr.sort);
									$("#HQ_paragraph").attr("sort_type", question_string.attr.sort_type);
									$("#HQ_paragraph").attr("disable_modal", 1);
									
									var HQ_paragraph = $("#HQ_paragraph");
									
									//Run question
									execute_run_queston( HQ_paragraph );
									
									//Remove the paragraph so if we crate a new one it will have the new values
									$('#HQ_paragraph').remove();
									
								}
							}
						}
					}					
				}
			}
		});
		
		//Check if we go over a row with the mouse
		$("#table_"+ts+ " td").live("mouseover mouseout", function(e) {	
			if ( e.type == "mouseover" ) {
				
				//If mouseover is a hidden question then make a pointer of the cursor
				if(check_hq_field($(this), questionID, questionattr, json)==true) $(this).css('cursor','pointer');
				
				//IPv4 regexp
	  			var reipv4 = new RegExp(/^(\d{1,3}\.){3}(\d{1,3})$|^(0x[\da-fA-F]{2}\.){3}(0x[\da-fA-F]{2})$|^(0[0-3][0-7]{2}\.){3}(0[0-3][0-7]{2})|^0x[\da-fA-F]{8}$|^[0-4]\d{9}$|^0[0-3]\d{10}$/g);
	  
				//IPv6 regexp
				var reipv6 = new RegExp(/^\s*((([0-9A-Fa-f]{1,4}:){7}([0-9A-Fa-f]{1,4}|:))|(([0-9A-Fa-f]{1,4}:){6}(:[0-9A-Fa-f]{1,4}|((25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])(.(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])){3})|:))|(([0-9A-Fa-f]{1,4}:){5}(((:[0-9A-Fa-f]{1,4}){1,2})|:((25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])(.(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])){3})|:))|(([0-9A-Fa-f]{1,4}:){4}(((:[0-9A-Fa-f]{1,4}){1,3})|((:[0-9A-Fa-f]{1,4})?:((25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])(.(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])){3}))|:))|(([0-9A-Fa-f]{1,4}:){3}(((:[0-9A-Fa-f]{1,4}){1,4})|((:[0-9A-Fa-f]{1,4}){0,2}:((25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])(.(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])){3}))|:))|(([0-9A-Fa-f]{1,4}:){2}(((:[0-9A-Fa-f]{1,4}){1,5})|((:[0-9A-Fa-f]{1,4}){0,3}:((25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])(.(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])){3}))|:))|(([0-9A-Fa-f]{1,4}:){1}(((:[0-9A-Fa-f]{1,4}){1,6})|((:[0-9A-Fa-f]{1,4}){0,4}:((25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])(.(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])){3}))|:))|(:(((:[0-9A-Fa-f]{1,4}){1,7})|((:[0-9A-Fa-f]{1,4}){0,5}:((25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])(.(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])){3}))|:)))(%.+)?\s*$/g);
				
				//If match the regex then do json call
				if ($(this).find("span:eq(0)").text().match(reipv4) || $(this).text().match(reipv6)) {
					
					//Set this span
					var this_span = $(this).find("span:eq(1)");
					
					//Check if we have to URL encode it
					var mySource_resolve = 'resolve?ip='+$(this).find("span:eq(0)").text();
					if(encode_url==1) mySource_resolve = urlencode(mySource_resolve);
					
					$.getJSON(mySource_resolve, function(data) {
						//Write to span
						if(data!="") this_span.text(" - "+data);
					});
					
					//Also do resolve with bl API, only with IPv4s
					if ($(this).find("span:eq(0)").text().match(reipv4)) {
						
						//Set this span
						var this_span = $(this).find("span:eq(2)");
						
						//Convert IP
						var temp_ip = $(this).find("span:eq(0)").text();
						temp_ip = temp_ip.split(".");
						temp_ip = temp_ip[3]+"."+temp_ip[2]+"."+temp_ip[1]+"."+temp_ip[0];
						
						
						//Check if we have to URL encode it
						var mySource_resolve_bl = 'resolve?ip='+ Config[0].http_bl_api_key +'.'+ temp_ip +'.dnsbl.httpbl.org';
						if(encode_url==1) mySource_resolve_bl = urlencode(mySource_resolve_bl);
						
						//Make the JSON call
						$.getJSON(mySource_resolve_bl, function(data) {
							var ip_info = data+"";
						  
							//Convert to what returned data is telling us
							if(ip_info!="") {
						  
								ip_info = ip_info.split(".");
							  
								var ip_type = "Unkown";
							  
								if(ip_info[3]==0) ip_type = "Search Engine";
								if(ip_info[3]==1) ip_type = "Suspicious";
								if(ip_info[3]==2) ip_type = "Harvester";
								if(ip_info[3]==3) ip_type = "Suspicious & Harvester";
								if(ip_info[3]==4) ip_type = "Comment Spammer";
								if(ip_info[3]==5) ip_type = "Suspicious & Comment Spammer";
								if(ip_info[3]==6) ip_type = "Harvester & Comment Spammer";
								if(ip_info[3]==7) ip_type = "Suspicious & Harvester & Comment Spammer";
							  
							  
								var ip_info_text = ip_type+", "; 
								ip_info_text = ip_info_text + "threat: "+ip_info[2]; 
								ip_info_text = ip_info_text + ", daysold: "+ip_info[1];

								//Write to span
								if(data!="") this_span.text(" - "+ip_info_text);
							  
							}
						  
						});
					}
				}
				
			} 
		});

	}

	
	/*
	--------------------------------------------------
	URL ENCODE FUNCTION BELOW
	--------------------------------------------------
	*/
	function urlencode(mySource) {
		var temp_value;
		//URL ENCODE
		temp_value = (mySource + '').toString();
		temp_value = encodeURIComponent(temp_value).replace(/!/g, '%21').replace(/'/g, '%27').replace(/\(/g, '%28').replace(/\)/g, '%29').replace(/\*/g, '%2A').replace(/%20/g, '+');
		//URL ENCODE END
				
		return temp_value;
	}
	
	/*
	--------------------------------------------------
	CHECK HIDDEN QUESTION FUNCTION BELOW
	--------------------------------------------------
	*/
	//Get title column
	function check_hq_field(thisis, questionID, questionattr, json) {
		var link_Array = thisis.attr("id").split("_");
		var table_position_number = parseInt(link_Array[0].replace("t", ""));
		//Check if the field have any hidden questions
		for(var i=0; i<Questions[questionID].children[questionattr].attr.link_Array.length; i++) {
			if(json.head[table_position_number].name==Questions[questionID].children[questionattr].attr.link_Array[i].name) {
				//Look for the right hidden question
				for (var j = 0; j < Questions.length; j++) {
					//If we find a hidden question that match with the column question then run it
					if(Questions[j].attr.id=="HQ") {
						for(var k = 0; k < Questions[j].children.length; k++) {
							if(Questions[j].children[k].attr.myid==Questions[questionID].children[questionattr].attr.link_Array[i].question) {
								return true;
							}
						}
					}
				}
			}
		}	
	}
	
	
	/*
	--------------------------------------------------
	RUN MODAL QUESTION FUNCTION BELOW
	--------------------------------------------------
	*/
	function run_modal_question(enterhit) {
		if(enterhit!=1) execute_run_queston($("#questionTree").jstree("get_selected"), 1);
		$( "#detailed_question" ).dialog( "close" );
		$( "#custom_query" ).dialog( "close" );
		$("#detailed_question_field").val("");
		$("#custom_question_field").val("");
	}
	
	/*
	--------------------------------------------------
	MAX LOAD TIME FUNCTION BELOW
	--------------------------------------------------
	*/
	//Create the div that we will write to
	$("<div id=\"alert_load_time_div\" style=\"overflow:hidden;\"><p>This query will take longer than <b id=\"show_alert_load_time\">"+alert_load_time+"</b> seconds, would you like to continue?</p><p class=\"mt10\"><button id=\"yes_run\">Yes</button> <button id=\"no_stop\">No</button></p><p class=\"mt10\">Remember? <input type=\"checkbox\" id=\"remember_alert_load_time\" /></p></div>").appendTo("body");
	$("#alert_load_time_div").dialog({
		autoOpen: false,
		title: "Warning",
		minHeight: 0,
		modal: true
	});
	//Make button to UI buttons
	$( "#yes_run, #no_stop" ).button();
	
	var auto_alert_load = 0;
	//If we hit yes, run question
	$("#yes_run").click(function () {
		//If remember is checked then save yes
		if($("#remember_alert_load_time").attr('checked') != undefined)	auto_alert_load = 1;
		$("#alert_load_time_div").dialog("close");
		//Run question
		execute_run_queston(tmp_question[0], tmp_question[1], 1);
	});
	
	//If we hit no, dont run question
	$("#no_stop").click(function () { 
		//If remember is checked then save no
		if($("#remember_alert_load_time").attr('checked') != undefined)	auto_alert_load = 2;
		$("#alert_load_time_div").dialog("close");
		//Make run question button normal
		$('input[id=button_run_question]').attr('checked', false);
		$("#button_run_question").button("refresh");
	});
		
	//Function for execute run question
	var tmp_question = new Array();
	function execute_run_queston(question, modal_question, ignore_alert) {
		
		//Change warning div time to the correct alert load time
		$("#show_alert_load_time").text(alert_load_time);
		
		//Get files
		var FileNames = '';
		var TotalFileSize = 0;
		TotalFileSize = parseInt(TotalFileSize);
		var checked_files = $("#fileTree .jstree-leaf.jstree-checked");
		$(checked_files).each(function(index) {
			FileNames += 'file=' + $( this ).attr('id') + '&';
			TotalFileSize += parseInt($( this ).attr('size'));
		});
		
		//Is auto alert setted?
		if(auto_alert_load==0) {
			//Warning if loadtime is to high
			if((TotalFileSize/LoadConstant)/1000>alert_load_time&&ignore_alert!=1) {
				tmp_question[0] = question;
				tmp_question[1] = modal_question;
				
				$("#alert_load_time_div").dialog("open");
				return false;
			}
		}
		
		//If auto load is set to no or then do not run run_question_function
		if(auto_alert_load==2&&(TotalFileSize/LoadConstant)/1000>alert_load_time) return false;
		
		//Run question
		run_question_function(question, modal_question, FileNames, TotalFileSize);
		
	}

});
