package icons;


import org.junit.Test;

import static org.junit.Assert.assertEquals;

public class DevSecOpsIconsTest {
    @Test
    public void scanIaCShouldHaveHeight() {
        int height = DevSecOpsIcons.ScanIaC.getIconHeight();
        assertEquals(16, height);
    }

    @Test
    public void scanImageShouldHaveHeight() {
        int height = DevSecOpsIcons.ScanImage.getIconHeight();
        assertEquals(16, height);
    }
}
