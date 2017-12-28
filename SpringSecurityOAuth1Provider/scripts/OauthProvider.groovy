import grails.codegen.model.Model
import groovy.transform.Field

@Field String usageMessage = """
Usage: grails s2-init-oauth2-provider <package> <client> <authorization-code> <access-token> <refresh-token>

Creates OAuth2 client, authorization code, access token and refresh token domain classes in specified package

Example: grails s2-init-oauth2=-provider com.yourapp OAuthConsumer
"""

@Field Map templateAttributes
@Field boolean uiOnly

description 'Creates artifacts for the Spring Security OAuth2 Provider plugin', {

	usage usageMessage

	argument name: 'Domain class package',          description: 'The package to use for the domain classes',   required: false
	argument name: 'OAuthConsumer class name',      description: 'The name of the Consumer class',              required: false

	flag name: 'uiOnly', description: 'If specified, no domain classes are created but the plugin settings are initialized'
}

Model oauthConsumerModel

uiOnly = flag('uiOnly')
if (uiOnly) {
	addStatus '\nConfiguring Spring Security OAuth Provider; not generating domain classes'
}
else {
	if (args.size() != 5) {
		error 'Usage:' + usageMessage
		return false
	}

	String packageName = args[0]

	oauthConsumerModel = model(packageName + '.' + args[1])

	addStatus "Creating Consumer class '${oauthConsumerModel.simpleName}' " +
			"in package '${packageName}'"

	templateAttributes = [
		packageName: packageName,
		OAuthConsumerClassName: oauthConsumerModel.simpleName,
	]

	createDomains oauthConsumerModel
}

updateConfig oauthConsumerModel?.simpleName

if (uiOnly) {
	addStatus '''
************************************************************
* Your grails-app/conf/application.groovy has been updated *
* with security settings; please verify that the           *
* values are correct.                                      *
************************************************************
'''
}
else {
	addStatus '''
************************************************************
* Created OAuth2-related domain classes. Your              *
* grails-app/conf/application.groovy has been updated with *
* the class names of the configured domain classes;        *
* please verify that the values are correct.               *
************************************************************
'''
}

addStatus '''
************************************************************
* Don't forget to update your security rules for the token *
* and authorization endpoints!                             *
************************************************************
'''

private void createDomains(Model oauthConsumerModel) {

	generateFile 'OAuthConsumer', oauthConsumerModel.packagePath, oauthConsumerModel.simpleName
}

private void updateConfig(String oauthConsumerClassName, String packageName) {

	file('grails-app/conf/application.groovy').withWriterAppend { BufferedWriter writer ->
		writer.newLine()
		writer.newLine()
		writer.writeLine '// Added by the Spring Security OAuth2 Provider plugin:'
		writer.writeLine "grails.plugin.springsecurity.oauthProvider.consumerLookup.className = '${packageName}.${oauthConsumerClassName}'"
		writer.newLine()
	}
}

private void generateFile(String templateName, String packagePath, String className) {
	render template(templateName + '.groovy.template'),
			file("grails-app/domain/$packagePath/${className}.groovy"),
			templateAttributes, false
}
