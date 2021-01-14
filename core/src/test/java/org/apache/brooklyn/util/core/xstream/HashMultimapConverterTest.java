package org.apache.brooklyn.util.core.xstream;

import com.google.common.base.Joiner;
import com.google.common.collect.HashMultimap;
import com.google.common.collect.ImmutableList;
import com.thoughtworks.xstream.XStream;
import junit.framework.TestCase;
import org.assertj.core.util.Strings;
import org.testng.Assert;
import org.testng.annotations.Test;

import java.net.Inet4Address;
import java.net.UnknownHostException;

public class HashMultimapConverterTest extends ConverterTestFixture {

    @Override
    protected void registerConverters(XStream xstream) {
        super.registerConverters(xstream);
        xstream.registerConverter(new HashMultimapConverter(xstream.getMapper()));
        xstream.registerConverter(new Inet4AddressConverter());
    }

    @Test
    public void testHashMultimapEmpty() throws UnknownHostException {
        String fmr = Strings.concat(
                "<com.google.common.collect.HashMultimap serialization=\"custom\">\n",
                "  <unserializable-parents/>\n",
                "  <com.google.common.collect.HashMultimap>\n",
                "    <default/>\n",
                "    <int>2</int>\n",
                "    <int>0</int>\n",
                "  </com.google.common.collect.HashMultimap>\n",
                "</com.google.common.collect.HashMultimap>");
        assertX(HashMultimap.create(), fmr);
    }

    @Test
    public void testHashMultimapBasic() throws UnknownHostException {
        String fmr = Strings.concat(
                "<com.google.common.collect.HashMultimap serialization=\"custom\">\n",
                "  <unserializable-parents/>\n",
                "  <com.google.common.collect.HashMultimap>\n",
                "    <default/>\n",
                "    <int>2</int>\n",
                "    <int>1</int>\n",
                "    <int>1</int>\n",
                "    <int>1</int>\n",
                "    <string>one</string>\n",
                "  </com.google.common.collect.HashMultimap>\n",
                "</com.google.common.collect.HashMultimap>");
        HashMultimap<Object, Object> hashMultimap = HashMultimap.create();
        hashMultimap.put(1, "one");
        assertX(hashMultimap, fmr);
    }

    @Test
    public void testHashMultimapMultikey() throws UnknownHostException {
        String fmr = Joiner.on("\n").join(
                        "<com.google.common.collect.HashMultimap serialization=\"custom\">",
        "  <unserializable-parents/>",
        "  <com.google.common.collect.HashMultimap>",
        "    <default/>",
        "    <int>2</int>",
        "    <int>3</int>",
        "    <string>one</string>",
        "    <int>1</int>",
        "    <string>one</string>",
        "    <string>two</string>",
        "    <int>2</int>",
        "    <string>two.two</string>",
        "    <string>two</string>",
        "    <string>three</string>",
        "    <int>1</int>",
        "    <string>three</string>",
        "  </com.google.common.collect.HashMultimap>",
        "</com.google.common.collect.HashMultimap>");

        HashMultimap<Object, Object> hashMultimap = HashMultimap.create();
        hashMultimap.put("one", "one");
        hashMultimap.put("two", "two");
        hashMultimap.put("two", "two.two");
        hashMultimap.put("three", "three");
        assertX(hashMultimap, fmr);
    }

    @Test
    public void testLegacyHashMultimap() throws UnknownHostException {
        HashMultimap<Object, Object> obj = HashMultimap.create();
        obj.put("myInet4Address", Inet4Address.getByName("1.1.1.1"));
        obj.put("mystring", "myval1");
        obj.put("mystring", "myval2");
        obj.put("myintholder", new XmlSerializerTest.IntegerHolder(123));

        String fmt = Joiner.on("\n").join(
                "<com.google.common.collect.HashMultimap serialization=\"custom\">",
                "  <unserializable-parents/>",
                "  <com.google.common.collect.HashMultimap>",
                "    <default/>",
                "    <int>2</int>",
                "    <int>3</int>",
                "    <string>myintholder</string>",
                "    <int>1</int>",
                "    <org.apache.brooklyn.util.core.xstream.XmlSerializerTest_-IntegerHolder>",
                "      <val>123</val>",
                "    </org.apache.brooklyn.util.core.xstream.XmlSerializerTest_-IntegerHolder>",
                "    <string>myInet4Address</string>",
                "    <int>1</int>",
                "    <java.net.Inet4Address>one.one.one.one/1.1.1.1</java.net.Inet4Address>",
                "    <string>mystring</string>",
                "    <int>2</int>",
                "    <string>myval1</string>",
                "    <string>myval2</string>",
                "  </com.google.common.collect.HashMultimap>",
                "</com.google.common.collect.HashMultimap>");

        assertX(obj, fmt);
    }
}