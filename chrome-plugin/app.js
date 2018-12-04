// page load
$(document).ready(function () {
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
            displayDomain(domain);
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

function displayDomain(domain){
    displayLoading(true);
    if (localStorage.getItem(domainKey(domain)) === null) {
        // domain key doesn't exist, create it
        localStorage[domainKey(domain)] = JSON.stringify({})
    }
    dict = JSON.parse(localStorage[domainKey(domain)])
    data_keys = [
        "bug_bounty",
        "google_transparency",
        "censys",
        "github",
        "gitlab",
        "virus_total",
        "grayhatwarfare"
    ];
    // Get data, if it's missing
    for (var i in data_keys){
        if (!(data_keys[i] in dict)){
            $("#loading").append('<br>Loading '+data_keys[i]+' data<br>');
            getData(data_keys[i],domain)
        }
    }
    $("#loading").append('<br>Done loading data<br>').delay(5000);
    // Done loading data, now display it
    // Create a string to hold temporary data
    var t = "";
    // Create a array to hold sub-domains
    var subDomains = [];
    // Create dict to hold our ip & port info
    var ips = {};

    data = JSON.parse(localStorage[domainKey(domain)]);

    // Load sub domain data
    $.each(data['virus_total']['subdomains'],function(index,item) {
        subDomains = appendArrayUniq(subDomains,item);
    });
    $.each(data['google_transparency'],function(index,item) {
        subDomains = appendArrayUniq(subDomains,item);
    });

    // Load IP/Port data
    $.each(data['censys']['results'],function(index,item) {
        $.each(data['censys']['results'][index]['protocols'],function(index,protocol) {
            ips = appendIP(ips,item['ip'],protocol)
        });
    });
   
    // Domain title
    $("#domain-title").html(domain+" <a href='#' class='domain-delete icon-trash' domain='"+domain+"'></a>");
    t = data['virus_total']['categories'].join(",")

    // Misc data
    html = "<li><b>VT Categories:</b> "+t+"</li>";
    arMisc = [
        'BitDefender category',
        'Forcepoint ThreatSeeker category',
        'Malwarebytes hpHosts info',
        'Websense ThreatSeeker category',
    ]
    $.each(arMisc,function(index,item) {
        if (data['virus_total'][item]){
            html += "<li><b>"+item+":</b> "+data['virus_total'][item]+"</li>";
        }
    });
    $("#Misc ul").html(html);

    // Display sub domains
    subDomains.sort();
    html = ""; 
    $.each(subDomains,function(i,sd) {
        html += `<div class="hide-children">
                    <li><i class="icon-plus"></i><a href="javascript:void(0)">`+sd+`</a></li>
                    <ul style="display: none">
                        <li><a href="http://`+sd+`" target="_blank"><i class="icon-share-alt"></i>http</a></li>
                        <li><a href="https://`+sd+`" target="_blank"><i class="icon-share-alt"></i>https</a></li>
                        <li><a href="https://censys.io/ipv4?q=`+sd+`" target="_blank"><i class="icon-share-alt"></i>censys.io</a></li>
                        <li><a href="https://www.shodan.io/search?query=`+sd+`" target="_blank"><i class="icon-share-alt"></i>shodan.io</a></li>
                    </ul>
                </div>`;
        
    });
    $("#Domains").html(html);

    // Display IP/Port data
    html = "";
    $.each(ips,function(key,val) {
        html += `<div class="hide-children">
                    <li><i class="icon-plus"></i><a href="javascript:void(0)">`+key+`</a></li>
                    <ul style="display: none">`;
        $.each(val,function(index,item) {
            html += `       <li>`+item+`</li>
                            <li>
                            <ul style="display: none">
                                <li><a href="https://censys.io/ipv4?q=`+item+`" target="_blank"><i class="icon-share-alt"></i>censys</a></li>
                                <li><a href="https://www.shodan.io/search?query=`+item+`" target="_blank"><i class="icon-share-alt"></i>shodan</a></li>
                            </ul>
                            </li>`;
        });
        html += `
                    </ul>
                </div>`
    });
    $("#IPs").html(html);

    // Repos
    html = "";
    $.each(data['github']['items'],function(i,item) {
        html +=`<li><a href="`+item['html_url']+`" target="_blank"><i class="icon-share-alt""></i>`+item['full_name']+`</a></li>`;
    });
    $("#Repos").html(html);

    // Buckets
    html = "";
    $.each(data['grayhatwarfare']['files'],function(i,item) {
        html +=`<li><a href="`+item['url']+`" target="_blank"><i class="icon-share-alt""></i>`+item['filename']+`</a></li>`;
    });
    $("#Buckets").html(html);
    displayLoading(false)
    loadMenu()
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
    if(!(dict[port])){
        dict[port]=[];
    }
    if ($.inArray(dict[port], ip)<0){
        dict[port].push(ip);
    }
    return dict
}

function displayLoading(status){
    if (status){
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
    localStorage[domainKey(domain)] = JSON.stringify(dict)
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
                async: false,
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
                async: false,
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
                async: false,
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
                async: false,
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
                async: false,
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
                async: false,
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
