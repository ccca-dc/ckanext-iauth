import ckan.plugins as plugins
import ckan.plugins.toolkit as toolkit


class IauthPlugin(plugins.SingletonPlugin):
    plugins.implements(plugins.IConfigurer)
    plugins.implements(plugins.IRoutes, inherit=True)

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
