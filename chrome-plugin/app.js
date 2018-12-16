// array of data we need to process
data_keys = [
    "bug_bounty",
    "google_transparency",
    "censys",
    "github",
    "gitlab",
    "virus_total",
    "grayhatwarfare"
];

// page load
$(document).ready(function () {
    // check if we're in developer mode and make that clear
    if (!('update_url' in chrome.runtime.getManifest())){
        $('.sidebar-header').html("DEVELOPER MODE");
    }

    // Sanity check, make sure we have our api keys
    if (
        !(localStorage.secret_virus_total_key)
        ||!(localStorage.secret_censys_uid)
        ||!(localStorage.secret_censys_key)
        ||!(localStorage.secret_grayhatwarfare_key)
        ) {
        getAPIKeys()
        //return
    }
    else {
        $('#content').hide();
        $('#sidebar').show();
        loadMenu()
    }
    
    // Settings button click
    $("#settings").click(function() {
        getAPIKeys()
    });

    // API Key form submit
    $("#save-keys").click(function() {
        localStorage.secret_virus_total_key = $("#virus-total-key").val();
        localStorage.secret_censys_uid = $("#censys-uid").val();
        localStorage.secret_censys_key = $("#censys-key").val();
        localStorage.secret_grayhatwarfare_key = $("#grayhatwarfare-key").val();
        showSecretsForm(false);
    });

    // New domain submit
    $("#new-domain").submit(function (event) {
        domain = $("input:first").val();
        var domain_match = new RegExp('^[a-z0-9-]{2,30}\.[a-z]{2,10}$');
        if (domain_match.test(domain)) {
            loadDomain(domain);
        }
        else {
            alert("NO domain match");
        }
        event.preventDefault();
    });

    // Click on left side bar menu item (domain)
    $(document).on("click", ".sidebar-link", function () {
        domain = $(this).attr("domain");
        displayDomain(domain);
    });

    // Click on top nav button
    $(document).on("click", ".top-nav-link", function () {
        var divID = "#" + $(this).text();
        $('.domain-data').hide();
        $(divID).show("slow", function () {
            // Animation complete.
        });
    });

    // Display/Hide all children
    $(document).on("click", ".hide-children", function () {
        $('ul', this).toggle();
    });

    // Delete domain click
    $(document).on("click", ".domain-delete", function () {
        domain = $(this).attr("domain");
        if (confirm('Delete data for '+domain+'?')) {
            localStorage.removeItem(domainKey(domain));
            location.reload();
        }
    });
});

function loadDomain(domain){
    // Counterintutive, set loading false here to clear the state and evaluate later
    displayLoading(false);

    if (localStorage.getItem(domainKey(domain)) === null) {
        // domain key doesn't exist, create it
        localStorage[domainKey(domain)] = JSON.stringify({})
    }
    dict = JSON.parse(localStorage[domainKey(domain)])

    // Get data, if it's missing
    for (var i in data_keys){
        if (!(data_keys[i] in dict)){
            console.log('Missing: '+data_keys[i]);
            displayLoading(true);
            $("#loading").append('<br>Loading '+data_keys[i]+' data<br>');
            getData(data_keys[i],domain)
        }
    }

    if ($('#loading').is(':hidden')){
        displayDomain(domain)
    }
}

function displayDomain(domain){
    // set selected_domain key to this domain name. Used later on when navigating. 
    localStorage['selected_domain'] = domain;
    data = JSON.parse(localStorage[domainKey(domain)])
    // Get data, if it's missing
    for (var i in data_keys){
        if (!(data_keys[i] in data)){
            console.log('Missing, not displaying: '+data_keys[i]);
            return
        }
    }
    $("#loading").append('<br>Done loading data<br>');

    // Start building dict (used for our tree view)
    tree = []
    tree.push({text: domain})


    // Load domain data
    temp_dict = {}
    c= Object.keys(data['censys']['results']).length + Object.keys(data['google_transparency']).length;
    temp_dict['text'] = 'Domains ('+c+')';
    temp_dict['icon'] = 'icon-plus';
    temp_dict['selectedIcon'] = 'icon-minus';
    // Temp array
    subDomains = [];
    // Load sub domain data
    $.each(data['virus_total']['subdomains'],function(index,item) {
        subDomains = appendArrayUniq(subDomains,{text: item});
    });
    $.each(data['google_transparency'],function(index,item) {
        subDomains = appendArrayUniq(subDomains,{text: item});
    });
    temp_dict['nodes'] = subDomains
    tree.push(temp_dict);

    // Load IP/Port data
    temp_dict = {}
    temp_dict['text'] = 'IPs ('+Object.keys(data['censys']['results']).length+')';
    temp_dict['icon'] = 'icon-plus';
    temp_dict['selectedIcon'] = 'icon-minus';
    portsIps = {};
    // Load IP/Port data
    $.each(data['censys']['results'],function(index,item) {
        $.each(data['censys']['results'][index]['protocols'],function(index,protocol) {
            portsIps = appendIP(portsIps,item['ip'],protocol)
        });
    });
    temp_dict['nodes'] = [];
    $.each(portsIps,function(key,value) {
        d = {};
        d['icon'] = 'icon-plus';
        d['selectedIcon'] = 'icon-minus';
        d['state'] = {
            checked: false,
            disabled: false,
            expanded: false,
            selected: false
        }
        d['text'] = key;
        d['nodes'] = [];
        $.each(value,function(index,item) {
            d['nodes'].push({text: item})
        });
        //console.log(d);
        temp_dict['nodes'].push(d);
    });
    //console.log(temp_dict);
    tree.push(temp_dict);

    // Load Buckets
    temp_dict = {}
    temp_dict['icon'] = 'icon-plus';
    temp_dict['selectedIcon'] = 'icon-minus';
    temp_dict['state'] = {
        checked: false,
        disabled: false,
        expanded: false,
        selected: false
    }
    temp_dict['nodes'] = [];
    c = 0;
    $.each(data['grayhatwarfare']['files'],function(i,item) {
        c += 1;
        temp_dict['nodes'].push({
            text: item['filename'],
            icon: "glyphicon glyphicon-stop",
            selectedIcon: "glyphicon glyphicon-stop",
            color: "#000000",
            backColor: "#FFFFFF",
            href: item['url'],
            selectable: true,
            state: {
              checked: false,
              disabled: false,
              expanded: false,
              selected: false
            },
            tags: ['available'],
            nodes: []
          });
    });
    temp_dict['text'] = 'Buckets ('+c+')';
    tree.push(temp_dict);

    // Load Repos
    temp_dict = {}
    temp_dict['text'] = 'Repos ('+Object.keys(data['github']['items']).length+')';
    temp_dict['icon'] = 'icon-plus';
    temp_dict['selectedIcon'] = 'icon-minus';
    temp_dict['state'] = {
        checked: false,
        disabled: false,
        expanded: false,
        selected: false
    }
    temp_dict['nodes'] = [];
    $.each(data['github']['items'],function(i,item) {
        temp_dict['nodes'].push({
            text: item['full_name'],
            icon: "glyphicon glyphicon-stop",
            selectedIcon: "glyphicon glyphicon-stop",
            color: "#000000",
            backColor: "#FFFFFF",
            href: item['html_url'],
            selectable: true,
            state: {
              checked: false,
              disabled: false,
              expanded: false,
              selected: false
            },
            tags: ['available'],
            nodes: []
          });
    });
    tree.push(temp_dict);


    tree['Repos'] = {}
    // GitHub
    tree['Repos']['GitHub'] = {};
    $.each(data['github']['items'],function(i,item) {
        tree['Repos']['GitHub'][item['full_name']] = item['html_url'];
    });

    $('#tree').treeview({
        data: tree,
        onNodeSelected: function(event, data) {
            treeNodeClicked(event, data);
        },
        onNodeUnselected: function(event, data) {
            treeNodeClicked(event, data);
        }
    });

    // Collapse tree
    $('#tree').treeview('collapseAll', { silent: true });
    // Select domain info
    $('#tree').treeview('selectNode', [0]);
    loadMenu();
    displayLoading(false);
}

function treeNodeClicked(event, data){
    domainData = JSON.parse(localStorage[domainKey(localStorage['selected_domain'])]);
    // Clear out more info
    $('#more-info').html(" ");
    //console.log(event);
    //console.log(data);
    if (!("icon" in data)){
        // It's one of: the domain name, an IP, or a sub-domain
        var dotCount = (data.text.match(/\./g) || []).length;
        if (data.nodeId == 0) {
            // Domain selected, show misc data
            
            $('#tree').treeview('collapseAll', { silent: true });
            html = "";
            arMisc = [
                'BitDefender category',
                'Forcepoint ThreatSeeker category',
                'Malwarebytes hpHosts info',
                'Websense ThreatSeeker category',
            ]
            $.each(arMisc,function(index,item) {
                if (domainData['virus_total'][item]){
                    html += "<b>"+item+"</b>: "+domainData['virus_total'][item]+"<br>";
                }
            });
            $('#more-info').html(html);
        }
        else if (dotCount == 3){
            // it's an IP
            html = '<p>'+data.text+'</p>'
            $.each(domainData['censys']['results'],function(index,item) {
                if (item['ip'] == data.text){
                    //console.log(domainData['censys']['results'][index]);
                    html += "<b>Location</b>: "+domainData['censys']['results'][index]['location.country']+"<br>";
                    html += "<b>Time Zone</b>: "+domainData['censys']['results'][index]['location.timezone']+"<br>";
                }
            });
            // Get reverse DNS for IP
            $.ajax({
                dataType: "json",
                url: "https://stat.ripe.net/data/reverse-dns-ip/data.json?resource="+data.text,
                data: data,
                async: false, 
                success: function(jd) {
                    html += "<b>Reverse DNS</b>: "+jd['data']['result'][0]+"<br>";
                }
            });
            // Get greynoise info
            $.ajax({
                dataType: "json",
                url: "https://viz.greynoise.io/api/ip/"+data.text,
                data: data,
                async: false, 
                success: function(jd) {
                    if (jd['records']=="unknown"){
                        html += "<b>Greynoise</b>: No Data</a><br>";
                    }
                    else {
                        html += "<b>Greynoise</b>: <a class='icon-share-alt' target='_blank' href='https://viz.greynoise.io/ip/"+data.text+"'></a><br>";
                    }
                    
                }
            });
            
            html += '<br><br>'
            html += '<p><a class="icon-share-alt" target="_blank" href="https://censys.io/ipv4?q='+data.text+'">Censys</a></p>'
            html += '<p><a class="icon-share-alt" target="_blank" href="https://www.shodan.io/search?query='+data.text+'">Shodan</a></p>'
            $('#more-info').html(html);
        }
        else {
            // it's a sub-domain
            html = '<p>'+data.text+'</p>'
            html += '<a class="icon-share-alt" target="_blank" href="https://censys.io/domain?q='+data.text+'">Censys</a></p>'
            html += '<p><a class="icon-share-alt" target="_blank" href="https://www.shodan.io/search?query='+data.text+'">Shodan</a></p>'
            $('#more-info').html(html);
        }
        return
    }
    if (data.icon == "icon-plus" && data.text.indexOf("/") != -1 && event.type == "nodeSelected"){
        // This is a port expend/collapse
        if (!data.state.expanded){
            $('#tree').treeview('expandNode', [data.nodeId, { levels: 1, silent: true, ignoreChildren: true }]);
        }
        else {
            $('#tree').treeview('collapseNode', [data.nodeId, { levels: 1, silent: true, ignoreChildren: true }]);
        }
        return
    }
    if ("href" in data){
        // Has a link, open it in a new tab
        var win = window.open(data.href, '_blank');
        win.focus();
        return
    }
    if (data.icon == "icon-plus" && event.type == "nodeSelected"){
        // Top level expandable node, collapse everything and expand this
        $('#tree').treeview('collapseAll', { silent: true });
        $('#tree').treeview('expandNode', [data.nodeId, { levels: 1, silent: true, ignoreChildren: true }]);
    }
}


function showSecretsForm(status){
    if (status){
        $('#content').hide();
        $('#sidebar').hide();
        $('#get-keys').show();
    }
    else {
        $('#content').show();
        $('#sidebar').show();
        $('#get-keys').hide();
    }
}

function appendArrayUniq(ar,item){
    if ($.inArray(item, ar)<0){
        ar.push(item);
    }
    return ar
}

function appendIP(dict,ip,port){
    d = {}
    d['text'] = port;
    d['icon'] = 'icon-plus';
    d['selectedIcon'] = 'icon-minus';
    d['state'] = {
        checked: false,
        disabled: false,
        expanded: false,
        selected: false
    }
    if(!(dict[port])){
        dict[port]=[];
    }
    if ($.inArray(dict[port], ip)<0){
        dict[port].push(ip);
    }
    return dict
}

function displayLoading(loading){
    if (loading){
        $('#content').hide();
        $('#loading').show();
    }
    else {
        $('#content').show();
        $('#loading').hide();
    }
}

function loadMenu(){
    // Clear current list
    $("#domain-list").html("");
    // Look through localStorage for every key starting with: domain_
    $.each(localStorage, function(key, value){
        if (key.startsWith("domain_")){
            // winner, winner, chicken dinner
            // transform to a standard domain format: domain.tld
            var ar = key.split("_");
            var domain = ar[1]+"."+ar[2];
            $("#domain-list").append("<li><a class='sidebar-link' domain='"+domain+"'>"+domain+"</a></li>");
        }
    });
}

function getAPIKeys(){
    $("#virus-total-key").val(localStorage.secret_virus_total_key);
    $("#censys-uid").val(localStorage.secret_censys_uid);
    $("#censys-key").val(localStorage.secret_censys_key);
    $("#grayhatwarfare-key").val(localStorage.secret_grayhatwarfare_key);
    showSecretsForm(true);
}

function domainKey(domain){
    // convert it to our local storage key name format
    var ar = domain.split(".");
    return 'domain_'+ar[0]+'_'+ar[1];
}

function updateDomainData(domain, k, v){
    // Get current data and update with new
    dict = JSON.parse(localStorage[domainKey(domain)])
    dict[k] = v;
    localStorage[domainKey(domain)] = JSON.stringify(dict);
    displayDomain(domain)
}

function getData(key,domain){
    switch(key){
        case 'grayhatwarfare':
            // remove tld from domain
            var ar = domain.split(".")
            searchString = ar[0]
            var url = "https://buckets.grayhatwarfare.com/api/v1/files/" + searchString + "?access_token=" + localStorage.secret_grayhatwarfare_key
            $.ajax({
                type: "GET",
                url: url,
                dataType: 'json',
                //async: false,
                success: function (data){
                    updateDomainData(domain,'grayhatwarfare', data);
                },
                error: function (data){
                    $("#loading").append('<br>ERROR loading Gray Hat Warfare data. Check your access key<br>');
                }
            });
            break;
        case 'virus_total':
            var url = "https://www.virustotal.com/vtapi/v2/domain/report?domain=" + domain + "&apikey=" + localStorage.secret_virus_total_key
            $.ajax({
                type: "GET",
                url: url,
                //async: false,
                dataType: 'json',
                success: function (data){
                    updateDomainData(domain,'virus_total', data);
                },
                error: function (data){
                    $("#loading").append('<br>ERROR loading Virus Total data. Check your access key<br>');
                }
            });
            break;
        case 'gitlab':
            // remove tld from domain
            var ar = domain.split(".")
            searchString = ar[0]
            var url = "https://gitlab.com/api/v4/projects?search=" + searchString
            $.ajax({
                type: "GET",
                url: url,
                //async: false,
                dataType: 'json',
                success: function (data){
                    updateDomainData(domain,'gitlab', data);
                }
            });
            break;
        case 'github':
            // remove tld from domain
            var ar = domain.split(".")
            searchString = ar[0]
            var url = "https://api.github.com/search/repositories?q=" + searchString
            $.ajax({
                type: "GET",
                url: url,
                //async: false,
                dataType: 'json',
                success: function (data){
                    updateDomainData(domain,'github', data);
                }
            });
            break;
        case 'censys':
            var url = "https://censys.io/api/v1/search/ipv4"
            $.ajax({
                type: "POST",
                url: url,
                //async: false,
                dataType: 'json',
                beforeSend: function (xhr) {
                    xhr.setRequestHeader('Authorization', 'Basic ' + btoa(localStorage.secret_censys_uid + ':' + localStorage.secret_censys_key));
                },
                data: '{"query" : "' + domain + '"}',
                success: function (data){
                    updateDomainData(domain,'censys', data);
                },
                error: function (data){
                    $("#loading").append('<br>ERROR loading Censys data. Check your access key<br>');
                }
            });
            break;
        case 'google_transparency':
            // Check Google's cert transparency report to find sub-domains
            var subDomainList = [];
            var url = "https://transparencyreport.google.com/transparencyreport/api/v3/httpsreport/ct/certsearch?include_expired=false&include_subdomains=true&domain=" + domain
            $.ajax({
                type: "GET",
                url: url,
                //async: false,
                dataType: 'text',
                success: function (data){
                    // Giberish in first two lines, remove them
                    var lines = data.split('\n');
                    lines.splice(0,2);
                    var dict = JSON.parse(lines.join('\n'));
                    // Loop through results and pull out found sub-domains
                    $.each(dict[0][1], function( index, value ) {
                        // add domain to our list/array if it's not already there
                        if (subDomainList.indexOf(value[1]) < 0) {
                            subDomainList.push(value[1]);
                        }
                    });
                    updateDomainData(domain,'google_transparency', subDomainList);
                },
                error: function (data){
                    $("#loading").append('<br>ERROR loading Censys data. Check your access key<br>');
                }
            });
            break;
        case 'bug_bounty':
            // check if we have our bug bounty list in local storage
            if (!(localStorage.data_bug_bounty)){
                // We don't have a copy of the bug bounty domain list, download it
                url = "https://raw.githubusercontent.com/arkadiyt/bounty-targets-data/master/data/domains.txt"
                $.get( url, function( data ) {
                    localStorage.data_bug_bounty = JSON.stringify(data.split("\n"));
                });
            }
            var bugBountyList = JSON.parse(localStorage.data_bug_bounty);

            // Hack to add missing domains to the list
            bugBountyList.push('google.com')

            // Check if our domain is in the list
            if ($.inArray(domain, bugBountyList) > 0) {
                updateDomainData(domain,'bug_bounty', true)
            }
            else {
                updateDomainData(domain,'bug_bounty', false)
            }
            break;
    }

}
