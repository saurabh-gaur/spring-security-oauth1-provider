import grails.test.AbstractCliTestCase

class OauthProviderTests extends AbstractCliTestCase {
    protected void setUp() {
        super.setUp()
    }

    protected void tearDown() {
        super.tearDown()
    }

    void testOauthProvider() {

        execute(["oauth-provider"])

        assertEquals 0, waitForProcess()
        verifyHeader()
    }
}
