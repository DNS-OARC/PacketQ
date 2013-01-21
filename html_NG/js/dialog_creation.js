	//Set X positon of dialog
	var dialog_position_x = 10;
	
	//Functions for create menu object
	function create_menu_object(id, name, disable, autoopen) {
		//Create the button to the menu
		$("#toolbar").append(" <input type=\"checkbox\" id=\"button_"+id+"\" /><label for=\"button_"+id+"\">"+name+"</label> ");
		$("#button_"+id).button();
		
		//Disable the buttun if its set to true
		if(disable==true) $("#button_"+id).button("disable");
		
		//Create the div that we will write to
		$("<div id=\""+id+"\" class=\"tal\" style=\"overflow:hidden;\"></div>").appendTo("body");
		
		//Option for the dialog box
		$( "#"+id ).dialog({
			autoOpen: false,
			position: [dialog_position_x, 100],
			title: name,
			minHeight: 0
		});
		dialog_position_x += 310;
		
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
	create_menu_object('custom_query', 'Custom Query', true);
	create_menu_object('files_in_folder', 'Selected Files', true);
	create_menu_object('run_question', 'Run question', true);
