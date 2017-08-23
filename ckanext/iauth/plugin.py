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
    plugins.implements(plugins.IOrganizationController, inherit=True)


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
            'organization_show': auth.organization_show,
            'package_show': auth.package_show,
            'package_delete': auth.package_delete,
            'package_update': auth.package_update,
            'resource_update': auth.resource_update,
            'resource_create': auth.resource_create,
            'user_list': auth.user_list,
            'user_show': auth.user_show,
            'group_show': auth.group_show
            }

    # IPackageController
    def after_delete(self, context, pkg_dict):

        pkg_name = ''
        try: # to purge
            user = context.get('auth_user_obj')
            pkg = context.get('package')
            if user and pkg:
                if user.id == pkg.creator_user_id and  pkg.private:
                    pkg_name = pkg.name
                    context['ignore_auth'] = True
                    logic.get_action('dataset_purge')(context,pkg_dict)
                    log.info('Dataset  %s purged', pkg_name)
                else:
                    log.info('Dataset  %s NOT purged - because not private or user != creator', pkg_name)
            else:
                log.info('Dataset  %s NOT purged - no context user or no context package', pkg_name)
        except:
            log.info('Dataset %s NOT purged and potentially NOT deleted', pkg_name)
