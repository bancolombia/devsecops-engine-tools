package icons;


import org.junit.Test;

import static org.junit.Assert.assertTrue;

public class DevSecOpsIconsTest {
    @Test
    public void scanIaCShouldHaveHeight() {
        int height = DevSecOpsIcons.ScanIaC.getIconHeight();
        assertTrue(height > 0);
    }

    @Test
    public void scanImageShouldHaveHeight() {
        int height = DevSecOpsIcons.ScanImage.getIconHeight();
        assertTrue(height > 0);
    }
}
