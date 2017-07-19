import ckan.plugins as plugins
import ckan.plugins.toolkit as toolkit
from ckanext.iauth.action import check_loaded_plugin
import ckanext.iauth.auth as auth

from ckanext.iauth.auth import package_delete
from ckanext.iauth.auth import resource_update
from ckanext.iauth.auth import package_update

class IauthPlugin(plugins.SingletonPlugin):
    plugins.implements(plugins.IConfigurer)
    plugins.implements(plugins.IRoutes, inherit=True)
    plugins.implements(plugins.IActions)
    plugins.implements(plugins.IAuthFunctions)


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
            'package_show': auth.package_show,
            'package_delete': auth.package_delete,
            'package_update': auth.package_update,
            'resource_update': auth.resource_update,
            'user_list': auth.user_list
            }
