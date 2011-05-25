/**
 * Copyright 2011 Glenn Maynard
 *
 * All rights reserved. Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.jivesoftware.smack.util;

import org.junit.Test;
import static org.junit.Assert.*;

public class StringPrepTest {
    static void checkStoredString(String expected, String from) throws StringPrep.StringPrepError {
        assertEquals(expected, StringPrep.prepAsStoredString(from));
    }

    static void checkQueryString(String expected, String from) throws StringPrep.StringPrepError {
        assertEquals(expected, StringPrep.prepAsQueryString(from));
    }

    /* Do a cursory test on the CharClass helper.  The functional tests later will
     * check this more thoroughly. */
    @Test public void charClasses() throws Exception {
        StringPrep.CharClass c1 = StringPrep.CharClass.fromRanges(new int[] {
            10, 20, 25, 30
        });

        for(int i = 0; i < 10; ++i)
            assertFalse(c1.isCharInClass(i));
        for(int i = 10; i <= 20; ++i)
            assertTrue(c1.isCharInClass(i));
        for(int i = 21; i < 25; ++i)
            assertFalse(c1.isCharInClass(i));
        for(int i = 25; i <= 30; ++i)
            assertTrue(c1.isCharInClass(i));
        for(int i = 31; i <= 40; ++i)
            assertFalse(c1.isCharInClass(i));
    }

    @Test public void charClassTestOverlaps() throws Exception {
        StringPrep.CharClass c2 = StringPrep.CharClass.fromRanges(new int[] {
            10, 20, 15, 25
        });
        for(int i = 0; i < 10; ++i)
            assertFalse(c2.isCharInClass(i));
        for(int i = 10; i <= 25; ++i)
            assertTrue(c2.isCharInClass(i));
        for(int i = 26; i <= 30; ++i)
            assertFalse(c2.isCharInClass(i));
    }

    @Test public void noChange1() throws Exception { checkStoredString("", ""); }
    @Test public void noChange2() throws Exception { checkStoredString(" ", " "); }
    @Test public void noChange3() throws Exception { checkStoredString("Simple text", "Simple text"); }

    // rfc4013 2.1. Mapping
    // B.1 Commonly mapped to nothing
    @Test public void mappedToNothing1() throws Exception { checkStoredString("", "\u200B"); }
    @Test public void mappedToNothing2() throws Exception { checkStoredString("", "\u00AD"); }
    @Test public void mappedToNothing3() throws Exception { checkStoredString("", "\uFEFF"); }
    @Test public void mappedToNothingMiddle() throws Exception { checkStoredString("before  after", "before \u200B after"); }

    // C.1.2 Non-ASCII space characters
    @Test public void mapToSpace1() throws Exception { checkStoredString(" ", "\u00A0"); }
    @Test public void mapToSpace2() throws Exception { checkStoredString(" ", "\u1680"); }
    @Test public void mapToSpace3() throws Exception { checkStoredString(" ", "\u2000"); }
    @Test public void mapToSpace4() throws Exception { checkStoredString(" ", "\u205F"); }
    @Test public void mapToSpace5() throws Exception { checkStoredString(" ", "\u3000"); }
    @Test public void notMappedToSpace1() throws Exception { checkStoredString("\u3001", "\u3001"); }
    @Test public void mapToSpaceMiddle() throws Exception { checkStoredString("Map to space", "Map\u00A0to\u00A0space"); }

    // rfc4013 2.2. Normalization: NFKC
    // We just call Normalizer.normalize for this; complete NFKC testing is its responsibility.
    // Do only a basic test to make sure it's happening.
    @Test public void testNFKC1() throws Exception { checkStoredString("a", "\u00AA"); }
    @Test public void testNFKC2() throws Exception { checkStoredString("I", "\u2160"); }
    @Test public void testNFKC3() throws Exception { checkStoredString("\u30A2\u30D1\u30FC\u30C8", "\u3300"); }

    // rfc4013 2.3. Prohibited Output
    // Non-ASCII space characters [StringPrep, C.1.2]
    // C.1.2 is mapped to space during Mapping.  Is there any way for NFKC to result in
    // a C.1.2 space?

    // ASCII control characters [StringPrep, C.2.1]
    @Test(expected=StringPrep.StringPrepProhibitedCharacter.class)
    public void asciiNil() throws Exception { StringPrep.prepAsStoredString("\000"); }
    @Test(expected=StringPrep.StringPrepProhibitedCharacter.class)
    public void asciiControlA() throws Exception { StringPrep.prepAsStoredString("\001"); }
    @Test(expected=StringPrep.StringPrepProhibitedCharacter.class)
    public void ascii7F() throws Exception { StringPrep.prepAsStoredString("\u007F"); }

    // Non-ASCII control characters [StringPrep, C.2.2]
    @Test(expected=StringPrep.StringPrepProhibitedCharacter.class)
    public void nonAscii80() throws Exception { StringPrep.prepAsStoredString("\u0080"); }

    @Test(expected=StringPrep.StringPrepProhibitedCharacter.class)
    public void nonAscii85() throws Exception { StringPrep.prepAsStoredString("\u0085"); }

    @Test(expected=StringPrep.StringPrepProhibitedCharacter.class)
    public void u2028() throws Exception { StringPrep.prepAsStoredString("\u2028"); }

    @Test(expected=StringPrep.StringPrepProhibitedCharacter.class)
    public void uFFFA() throws Exception { StringPrep.prepAsStoredString("\uFFFA"); }

    @Test(expected=StringPrep.StringPrepProhibitedCharacter.class) // U+1D173
    public void musicalControlCharacter1() throws Exception { StringPrep.prepAsStoredString("\uD834\uDD73"); }

    @Test(expected=StringPrep.StringPrepProhibitedCharacter.class) // U+1D17A
    public void musicalControlCharacter2() throws Exception { StringPrep.prepAsStoredString("\uD834\uDD7A"); }

    // Private Use characters [StringPrep, C.3]
    @Test(expected=StringPrep.StringPrepProhibitedCharacter.class) // U+E000
    public void plane0PrivateUse1() throws Exception { StringPrep.prepAsStoredString("\uE000"); }
    @Test(expected=StringPrep.StringPrepProhibitedCharacter.class) // U+E001
    public void plane0PrivateUse2() throws Exception { StringPrep.prepAsStoredString("\uE001"); }
    @Test(expected=StringPrep.StringPrepProhibitedCharacter.class) // U+F0000
    public void plane15PrivateUse1() throws Exception { StringPrep.prepAsStoredString("\uDB80\uDC00"); }
    @Test(expected=StringPrep.StringPrepProhibitedCharacter.class) // U+F0001
    public void plane15PrivateUse2() throws Exception { StringPrep.prepAsStoredString("\uDB80\uDC01"); }
    @Test(expected=StringPrep.StringPrepProhibitedCharacter.class) // U+100000
    public void plane16PrivateUse1() throws Exception { StringPrep.prepAsStoredString("\uDBC0\uDC00"); }
    @Test(expected=StringPrep.StringPrepProhibitedCharacter.class) // U+100001
    public void plane16PrivateUse2() throws Exception { StringPrep.prepAsStoredString("\uDBC0\uDC01"); }

    // Non-character code points [StringPrep, C.4]
    @Test(expected=StringPrep.StringPrepProhibitedCharacter.class) // U+FDD0
    public void nonCharacterCodepoint1() throws Exception { StringPrep.prepAsStoredString("\uFDD0"); }
    @Test(expected=StringPrep.StringPrepProhibitedCharacter.class) // U+FDD1
    public void nonCharacterCodepoint2() throws Exception { StringPrep.prepAsStoredString("\uFDD1"); }
    @Test(expected=StringPrep.StringPrepProhibitedCharacter.class) // U+10FFFE
    public void nonCharacterCodepoint3() throws Exception { StringPrep.prepAsStoredString("\uDBFF\uDFFE"); }

    // Surrogate code points [StringPrep, C.5]
    // C5 doesn't apply, as UTF-16 is our internal representation; the conversion from UTF-16
    // to the transport encoding (UTF-8) removes them.

    // Inappropriate for plain text characters [StringPrep, C.6]
    @Test(expected=StringPrep.StringPrepProhibitedCharacter.class) // U+FFF9
    public void plainTextInappropriateCodepoint1() throws Exception { StringPrep.prepAsStoredString("\uFFF9"); }

    // Inappropriate for canonical representation characters [StringPrep, C.7]
    @Test(expected=StringPrep.StringPrepProhibitedCharacter.class) // U+2FF0
    public void canonicalInappropriateCodepoint1() throws Exception { StringPrep.prepAsStoredString("\u2FF0"); }
    @Test(expected=StringPrep.StringPrepProhibitedCharacter.class) // U+2FF1
    public void canonicalInappropriateCodepoint2() throws Exception { StringPrep.prepAsStoredString("\u2FF1"); }
    @Test(expected=StringPrep.StringPrepProhibitedCharacter.class) // U+2FFB
    public void canonicalInappropriateCodepoint3() throws Exception { StringPrep.prepAsStoredString("\u2FFB"); }

    // Change display properties or deprecated characters [StringPrep, C.8]
    @Test(expected=StringPrep.StringPrepProhibitedCharacter.class) // U+206F
    public void deprecatedCodepoint1() throws Exception { StringPrep.prepAsStoredString("\u206F"); }

    // Tagging characters [StringPrep, C.9]
    @Test(expected=StringPrep.StringPrepProhibitedCharacter.class) // U+E0001
    public void taggingCharacters1() throws Exception { StringPrep.prepAsStoredString("\uDB40\uDC01"); }
    @Test(expected=StringPrep.StringPrepProhibitedCharacter.class) // U+E0025
    public void taggingCharacters2() throws Exception { StringPrep.prepAsStoredString("\uDB40\uDC25"); }


    // 2.4. Bidirectional Characters [StringPrep, Section 6]
    @Test(expected=StringPrep.StringPrepRTLErrorBothRALandL.class) // U+05BE
    public void RandALandLCat1() throws Exception { StringPrep.prepAsStoredString("ascii \u05BE"); }

    @Test(expected=StringPrep.StringPrepRTLErrorBothRALandL.class) // U+0785
    public void RandALandLCat2() throws Exception { StringPrep.prepAsStoredString("ascii \u0785"); }

    @Test(expected=StringPrep.StringPrepRTLErrorRALWithoutPrefix.class)
    public void RandALandLCatWithoutPrefix() throws Exception { StringPrep.prepAsStoredString("1__\u05BE"); }

    @Test(expected=StringPrep.StringPrepRTLErrorRALWithoutSuffix.class)
    public void RandALandLCatWithoutSuffix() throws Exception { StringPrep.prepAsStoredString("\u05BE__1"); }

    @Test public void correctRTL() throws Exception { checkStoredString("\u05BE_123_\u0785", "\u05BE_123_\u0785"); }

    // 2.5. Unassigned Code Points [StringPrep, Section 7]
    // Strings with unassigned codepoints fail in Stored String mode, and are left untouched
    // in Query String mode.
    @Test(expected=StringPrep.StringPrepUnassignedCodepoint.class) // U+0221
    public void BMPUnassigned1Stored() throws Exception { StringPrep.prepAsStoredString("\u0221"); }

    @Test(expected=StringPrep.StringPrepUnassignedCodepoint.class) // U+0235
    public void BMPUnassigned2Stored() throws Exception { StringPrep.prepAsStoredString("\u0235"); }

    @Test public void BMPUnassigned1Query() throws Exception { checkQueryString("\u0221", "\u0221"); }
    @Test public void BMPUnassigned2Query() throws Exception { checkQueryString("\u0235", "\u0235"); }
}
