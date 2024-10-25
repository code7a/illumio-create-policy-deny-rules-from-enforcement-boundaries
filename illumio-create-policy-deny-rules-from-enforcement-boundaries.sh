#illumio-create-policy-deny-rules-from-enforcement-boundaries
#
#Licensed under the Apache License, Version 2.0 (the "License"); you may not
#use this file except in compliance with the License. You may obtain a copy of
#the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
#Unless required by applicable law or agreed to in writing, software
#distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#License for the specific language governing permissions and limitations under
#the License.
#
#version="0.0.2"
#
#This script will create new policy, all scoped rule sets, with deny rules from enforcement bounaries.
#
#jq is required to parse results
#https://stedolan.github.io/jq/
#

get_jq_version(){
    jq_version=$(jq --version)
    if [ $(echo $?) -ne 0 ]; then
        echo "jq application not found. jq is a command line JSON processor and is used to process and filter JSON inputs."
        echo "Reference: https://stedolan.github.io/jq/"
        echo "Please install jq, i.e. yum install jq"
        exit 1
    fi
}

get_config_yml(){
    source $BASEDIR/.illumio_config.yml >/dev/null 2>&1 || get_illumio_vars
}

get_illumio_vars(){
    echo ""
    read -p "Enter illumio PCE domain: " ILLUMIO_PCE_DOMAIN
    read -p "Enter illumio PCE port: " ILLUMIO_PCE_PORT
    read -p "Enter illumio PCE organization ID: " ILLUMIO_PCE_ORG_ID
    read -p "Enter illumio PCE API username: " ILLUMIO_PCE_API_USERNAME
    echo -n "Enter illumio PCE API secret: " && read -s ILLUMIO_PCE_API_SECRET && echo ""
    cat << EOF > $BASEDIR/.illumio_config.yml
export ILLUMIO_PCE_DOMAIN=$ILLUMIO_PCE_DOMAIN
export ILLUMIO_PCE_PORT=$ILLUMIO_PCE_PORT
export ILLUMIO_PCE_ORG_ID=$ILLUMIO_PCE_ORG_ID
export ILLUMIO_PCE_API_USERNAME=$ILLUMIO_PCE_API_USERNAME
export ILLUMIO_PCE_API_SECRET=$ILLUMIO_PCE_API_SECRET
EOF
}

create_deny_rules(){
    echo ""
    echo "Creating rule sets and deny rules..."
    echo ""
    #get enforcement boundaries
    enforcement_boundaries=$(curl -s "https://$ILLUMIO_PCE_API_USERNAME:$ILLUMIO_PCE_API_SECRET@$ILLUMIO_PCE_DOMAIN:$ILLUMIO_PCE_PORT/api/v2/orgs/$ILLUMIO_PCE_ORG_ID/sec_policy/active/enforcement_boundaries")
    #for each enforcement boundaries deny rule, create a deny rule in the above rule set
    echo "$enforcement_boundaries" | jq -c '.[]' | while read -r obj; do
        name=$(echo $obj | jq -rc .name)
        providers=$(echo $obj | jq -rc .providers)
        consumers=$(echo $obj | jq -rc .consumers)
        ingress_services=$(echo $obj | jq -rc .ingress_services)
        network_type=$(echo $obj | jq -rc .network_type)
        enabled=$(echo $obj | jq -rc .enabled)
        #create rule set
        rule_sets_post=$(curl -s https://$ILLUMIO_PCE_API_USERNAME:$ILLUMIO_PCE_API_SECRET@$ILLUMIO_PCE_DOMAIN:$ILLUMIO_PCE_PORT/api/v2/orgs/$ILLUMIO_PCE_ORG_ID/sec_policy/draft/rule_sets -X POST -H 'content-type: application/json' --data-raw '{"name":"'$name'","description":"","scopes":[[]]}')
        #get href
        rule_sets_post_href=$(echo $rule_sets_post | jq -r .href)
        #post deny rules
        curl https://$ILLUMIO_PCE_API_USERNAME:$ILLUMIO_PCE_API_SECRET@$ILLUMIO_PCE_DOMAIN:$ILLUMIO_PCE_PORT/api/v2$rule_sets_post_href/deny_rules -X POST -H 'content-type: application/json' --data-raw '{"providers":'$providers',"consumers":'$consumers',"enabled":'$enabled',"ingress_services":'$ingress_services',"egress_services":[],"network_type":"'$network_type'","description":""}'
        echo ""
    done
    echo ""
    echo "Process complete. Exiting."
}

BASEDIR=$(dirname -- $0)

get_jq_version

get_config_yml

create_deny_rules

exit 0