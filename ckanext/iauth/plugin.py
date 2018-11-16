import ckan.plugins as plugins
import ckan.plugins.toolkit as toolkit
from ckanext.iauth.action import check_loaded_plugin
import ckanext.iauth.auth as auth
import ckan.logic as logic

from ckanext.iauth.auth import package_delete
from ckanext.iauth.auth import resource_update
from ckanext.iauth.auth import package_update
import logging

from ckanext.iauth import helpers


log = logging.getLogger(__name__)

class IauthPlugin(plugins.SingletonPlugin):
    plugins.implements(plugins.IConfigurer)
    plugins.implements(plugins.IRoutes, inherit=True)
    plugins.implements(plugins.ITemplateHelpers)
    plugins.implements(plugins.IActions)
    plugins.implements(plugins.IAuthFunctions)
    plugins.implements(plugins.IPackageController, inherit=True)


    # IConfigurer
    def update_config(self, config_):
        toolkit.add_template_directory(config_, 'templates')
        toolkit.add_public_directory(config_, 'public')
        toolkit.add_resource('fanstatic', 'iauth')

    # IRoutes
    def before_map(self, map):
        # download not possible for anonymous user
        map.connect('resource_download', '/dataset/{id}/resource/{resource_id}/download/{filename}',
                    controller='ckanext.iauth.controllers.package_override:PackageContributeOverride',
                    action='resource_download')

        return map

    # ITemplateHelpers
    def get_helpers(self):
        return {
            'iauth_get_special_org': helpers.iauth_get_special_org,
            'iauth_check_admin': helpers.iauth_check_admin,
            'iauth_check_controller_org': helpers.iauth_check_controller_org,
            'iauth_check_controller_user': helpers.iauth_check_controller_user,
            'iauth_anon_activity': helpers.iauth_anon_activity
            }


    # IActions
    def get_actions(self):
        actions = {
            'check_loaded_plugin': check_loaded_plugin
            }
        return actions

    # IAuthFunctions
    def get_auth_functions(self):
        """Implements IAuthFunctions.get_auth_functions"""
        return {
            'package_search': auth.package_search,
            'package_show': auth.package_show,
            'package_delete': auth.package_delete,
            'package_create': auth.package_create,
            'package_update': auth.package_update,
            'resource_update': auth.resource_update,
            'resource_create': auth.resource_create,
            'member_create': auth.member_create,
            'member_delete': auth.member_delete
            # We Need default CKAN ... (= all open)
            #'organization_show': auth.organization_show,
            #'user_list': auth.user_list,
            #'user_show': auth.user_show,
            #'group_show': auth.group_show
            }

# IPackageController
    def after_delete(self, context, pkg_dict):

        # Georg, Kathi, Anja am 15.11.2017:
        # We purge after all deletes EXCEPT when the user is a sysadmins
        # because: sysadmins can use purge themselves, but we need to really delete the names
        # delete is for normal users only allowed for datasets which are private!

        pkg_name = ''
        user = context.get('auth_user_obj')
        pkg = context.get('package')
        if pkg:
            pkg_name = pkg.name
        else:
            pkg_name = pkg_dict['id']

        # Kathi/Anja 16.11.2018 - Check Baskets
        if check_loaded_plugin(context, {'name':'basket'}):

            try:
                 # remove pkg from all baskets
                baskets = toolkit.get_action('package_basket_list')(context, {'id': pkg_dict['id']})
                for basket in baskets:
                    toolkit.get_action('basket_element_remove')(context, {'basket_id': basket, 'package_id': pkg_dict['id']})
            except:
                pass
        try: # to purge
            if user and not user.sysadmin:
                context['ignore_auth'] = True
                logic.get_action('dataset_purge')(context,pkg_dict)
                log.info('Dataset  %s purged', pkg_name)
            else:
                log.info('Dataset  %s NOT purged - because user is sysadmin', pkg_name)

        except:
            log.info('Dataset %s NOT purged and potentially NOT deleted', pkg_name)
