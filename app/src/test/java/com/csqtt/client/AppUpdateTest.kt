package com.csqtt.client

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.json.JSONObject
import org.junit.Test

class AppUpdateTest {
    @Test
    fun comparesVersionsNumerically() {
        assertTrue(isNewerVersion("1.9.9", "2.0.5"))
        assertTrue(isNewerVersion("2.0", "2.0.1"))
        assertFalse(isNewerVersion("2.0.5", "2.0"))
        assertFalse(isNewerVersion("2.1.0", "2.0.9"))
        assertFalse(isNewerVersion("2.0.5", "invalid"))
        assertTrue(isNewerVersion("2.5.0.4", "v2.5.0.5"))
    }

    @Test
    fun acceptsOnlyCompatibleAndroidReleaseTags() {
        assertEquals("v2.5.0.4", compatibleAndroidVersion("csqtt-android-v2.5.0.4"))
        for (tag in listOf("v9.0.0", "csqtt-server-v9.0.0", "csqtt-android-v2.5.0.5-beta", "csqtt-android-vbad")) {
            assertNull(compatibleAndroidVersion(tag))
        }
    }

    @Test
    fun ignoresDraftsPrereleasesAndUnrelatedProjects() {
        val release = JSONObject().put("tag_name", "csqtt-android-v2.5.0.4")
            .put("html_url", "https://github.com/mikhail384/tunnelscope/releases/tag/csqtt-android-v2.5.0.4")
        assertEquals("v2.5.0.4", release.toAppReleaseInfo()?.versionTag)
        assertNull(release.put("draft", true).toAppReleaseInfo())
        assertNull(release.put("draft", false).put("prerelease", true).toAppReleaseInfo())
        assertNull(release.put("prerelease", false).put("tag_name", "v99.0.0").toAppReleaseInfo())
    }
}
