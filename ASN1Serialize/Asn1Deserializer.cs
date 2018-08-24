using System;
using System.Buffers;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Numerics;
using System.Reflection;
using System.Security.Cryptography;
using System.Security.Cryptography.Asn1;

namespace ASN1Serialize
{
    /// <summary>
    /// A doodle, taking Asn1V2.Serializer.cs, and taking the deserializer bits
    /// to make them work like I've outlined in Program.cs.
    /// </summary>
    internal static class Asn1Deserializer
    {
        internal delegate object Deserializer(AsnReader reader);
        private delegate bool TryDeserializer<T>(AsnReader reader, out T value);
        private const BindingFlags FieldFlags
            = BindingFlags.Public | BindingFlags.NonPublic | BindingFlags.Instance;
        private static readonly ConcurrentDictionary<Type, FieldInfo[]> s_orderedFields
            = new ConcurrentDictionary<Type, FieldInfo[]>();

        public static T Deserialize<T>(ReadOnlyMemory<byte> source, AsnEncodingRules ruleSet)
            => Deserialize<T>(source, ruleSet, out _);

        public static T Deserialize<T>(ReadOnlyMemory<byte> source, AsnEncodingRules ruleSet, out int bytesRead)
        {
            Deserializer deserializer = GetDeserializer(typeof(T), null);
            AsnReader reader = new AsnReader(source, ruleSet);
            ReadOnlyMemory<byte> firstElement = reader.PeekEncodedValue();

            T t = (T)deserializer(reader);
            bytesRead = firstElement.Length;
            return t;
        }

        private static Deserializer GetDeserializer(Type typeT, FieldInfo fieldInfo, bool useExpectedTag = true, AsnTypeAttribute parentAsnType = null)
        {
            Deserializer literalValueDeserializer = GetSimpleDeserializer(
                typeT,
                fieldInfo,
                useExpectedTag,
                parentAsnType,
                out SerializerFieldData fieldData);

            Deserializer deserializer = literalValueDeserializer;

            if (fieldData.HasExplicitTag)
            {
                deserializer = ExplicitValueDeserializer(deserializer, fieldData.ExpectedTag);
            }

            if (fieldData.IsOptional || fieldData.DefaultContents != null)
            {
                Asn1Tag? expectedTag = null;

                if (fieldData.SpecifiedTag || fieldData.TagType != null)
                {
                    expectedTag = fieldData.ExpectedTag;
                }

                deserializer = DefaultValueDeserializer(
                    deserializer,
                    literalValueDeserializer,
                    fieldData.IsOptional,
                    fieldData.DefaultContents,
                    expectedTag);
            }

            return deserializer;
        }

        private static Deserializer GetSimpleDeserializer(
            Type typeT,
            FieldInfo fieldInfo,
            bool useExpectedTag,
            AsnTypeAttribute parentAsnType,
            out SerializerFieldData fieldData)
        {
            if (!typeT.IsSealed || typeT.ContainsGenericParameters)
            {
                throw new AsnSerializationConstraintException(
                    SR.Format(SR.Cryptography_AsnSerializer_NoOpenTypes, typeT.FullName));
            }

            GetFieldInfo(typeT, fieldInfo, parentAsnType, out fieldData);

            SerializerFieldData localFieldData = fieldData;
            typeT = UnpackIfNullable(typeT);

            // TODO: Should this be lower? In theory, if an Attribute implements Deserialize,
            // it means that it has to do everything itself anyway.
            var asnTypeDeserializer = localFieldData.AsnType?.Deserialize;
            if (asnTypeDeserializer != null)
            {
                return asnTypeDeserializer;
            }

            if (fieldData.IsAny)
            {
                if (typeT == typeof(ReadOnlyMemory<byte>))
                {
                    Asn1Tag matchTag = fieldData.ExpectedTag;

                    // EXPLICIT Any can't be validated, just return the value.
                    if (fieldData.HasExplicitTag || !fieldData.SpecifiedTag)
                    {
                        return reader => reader.GetEncodedValue();
                    }

                    // If it's not declared EXPLICIT but an [ExpectedTag] was provided,
                    // use it as a validation/filter.
                    return reader =>
                    {
                        Asn1Tag nextTag = reader.PeekTag();

                        if (matchTag.TagClass != nextTag.TagClass ||
                            matchTag.TagValue != nextTag.TagValue)
                        {
                            throw new CryptographicException(SR.Cryptography_Der_Invalid_Encoding);
                        }

                        return reader.GetEncodedValue();
                    };
                }

                throw new AsnSerializationConstraintException(
                    SR.Format(SR.Cryptography_AsnSerializer_UnhandledType, typeT.FullName));
            }

            if (GetChoiceAttribute(typeT) != null)
            {
                return reader => DeserializeChoice(reader, typeT);
            }

            Debug.Assert(fieldData.TagType != null);

            Asn1Tag expectedTag = fieldData.HasExplicitTag || !useExpectedTag
                ? new Asn1Tag(fieldData.TagType.Value)
                : fieldData.ExpectedTag;

            if (typeT.IsPrimitive)
            {
                // The AsnTypeAttribute resolved in GetFieldInfo currently doesn't allow
                // type modification for any of the primitive types.  If that changes, we
                // need to either pass it through here or do some other form of rerouting.
                //Debug.Assert(!fieldData.WasCustomized);

                return GetPrimitiveDeserializer(typeT, expectedTag);
            }

            if (typeT.IsEnum)
            {
                if (typeT.GetCustomAttributes(typeof(FlagsAttribute), false).Length > 0)
                {
                    return reader => reader.GetNamedBitListValue(expectedTag, typeT);
                }

                return reader => reader.GetEnumeratedValue(expectedTag, typeT);
            }

            if (typeT == typeof(string))
            {
                if (fieldData.TagType == UniversalTagNumber.ObjectIdentifier)
                {
                    return reader => reader.ReadObjectIdentifierAsString(expectedTag);
                }

                // Because all string types require an attribute saying their type, we'll
                // definitely have a value.
                Debug.Assert(localFieldData.TagType != null);
                UniversalTagNumber encoding = localFieldData.TagType.Value;
                if (localFieldData.AsnType is GeneralStringAttribute gsa)
                {
                    encoding = gsa.EncodingType;
                }
                return reader => reader.GetCharacterString(expectedTag, encoding);
            }

            if (typeT == typeof(ReadOnlyMemory<byte>) && fieldData.IsNotCollection)
            {
                if (fieldData.TagType == UniversalTagNumber.BitString)
                {
                    return reader =>
                    {
                        if (reader.TryGetPrimitiveBitStringValue(expectedTag, out _, out ReadOnlyMemory<byte> contents))
                        {
                            return contents;
                        }

                        // Guaranteed too big, because it has the tag and length.
                        int length = reader.PeekEncodedValue().Length;
                        byte[] rented = ArrayPool<byte>.Shared.Rent(length);

                        try
                        {
                            if (reader.TryCopyBitStringBytes(expectedTag, rented, out _, out int bytesWritten))
                            {
                                return new ReadOnlyMemory<byte>(rented.AsSpan(0, bytesWritten).ToArray());
                            }

                            Debug.Fail("TryCopyBitStringBytes produced more data than the encoded size");
                            throw new CryptographicException();
                        }
                        finally
                        {
                            Array.Clear(rented, 0, length);
                            ArrayPool<byte>.Shared.Return(rented);
                        }
                    };
                }

                if (fieldData.TagType == UniversalTagNumber.OctetString)
                {
                    return reader =>
                    {
                        if (reader.TryGetPrimitiveOctetStringBytes(expectedTag, out ReadOnlyMemory<byte> contents))
                        {
                            return contents;
                        }

                        // Guaranteed too big, because it has the tag and length.
                        int length = reader.PeekEncodedValue().Length;
                        byte[] rented = ArrayPool<byte>.Shared.Rent(length);

                        try
                        {
                            if (reader.TryCopyOctetStringBytes(expectedTag, rented, out int bytesWritten))
                            {
                                return new ReadOnlyMemory<byte>(rented.AsSpan(0, bytesWritten).ToArray());
                            }

                            Debug.Fail("TryCopyOctetStringBytes produced more data than the encoded size");
                            throw new CryptographicException();
                        }
                        finally
                        {
                            Array.Clear(rented, 0, length);
                            ArrayPool<byte>.Shared.Return(rented);
                        }
                    };
                }

                if (fieldData.TagType == UniversalTagNumber.Integer)
                {
                    return reader => reader.GetIntegerBytes(expectedTag);
                }

                Debug.Fail($"No ReadOnlyMemory<byte> handler for {fieldData.TagType}");
                throw new CryptographicException();
            }

            if (typeT == typeof(Oid))
            {
                bool skipFriendlyName = !fieldData.PopulateOidFriendlyName.GetValueOrDefault();
                return reader => reader.ReadObjectIdentifier(expectedTag, skipFriendlyName);
            }

            if (typeT.IsArray)
            {
                if (typeT.GetArrayRank() != 1)
                {
                    throw new AsnSerializationConstraintException(
                        SR.Format(SR.Cryptography_AsnSerializer_NoMultiDimensionalArrays, typeT.FullName));
                }

                Type baseType = typeT.GetElementType();

                if (baseType.IsArray)
                {
                    throw new AsnSerializationConstraintException(
                        SR.Format(SR.Cryptography_AsnSerializer_NoJaggedArrays, typeT.FullName));
                }

                return reader =>
                {
                    LinkedList<object> linkedList = new LinkedList<object>();

                    AsnReader collectionReader;

                    if (localFieldData.TagType == UniversalTagNumber.SetOf)
                    {
                        collectionReader = reader.ReadSetOf(expectedTag);
                    }
                    else
                    {
                        Debug.Assert(localFieldData.TagType == 0 || localFieldData.TagType == UniversalTagNumber.SequenceOf);
                        collectionReader = reader.ReadSequence(expectedTag);
                    }

                    var localAsnType = localFieldData.AsnType;
                    if (localAsnType is SequenceOfAttribute sofa)
                    {
                        localAsnType = Activator.CreateInstance(sofa.FieldTypeAsnAttribute) as AsnTypeAttribute;
                    }

                    Deserializer deserializer = GetDeserializer(baseType, null, true, localAsnType);

                    while (collectionReader.HasData)
                    {
                        object elem = deserializer(collectionReader);
                        LinkedListNode<object> node = new LinkedListNode<object>(elem);
                        linkedList.AddLast(node);
                    }

                    object[] objArr = linkedList.ToArray();
                    Array arr = Array.CreateInstance(baseType, objArr.Length);
                    Array.Copy(objArr, arr, objArr.Length);
                    return arr;
                };
            }

            if (typeT == typeof(DateTimeOffset))
            {
                if (fieldData.TagType == UniversalTagNumber.UtcTime)
                {
                    if (fieldData.TwoDigitYearMax != null)
                    {
                        return reader =>
                            reader.GetUtcTime(expectedTag, localFieldData.TwoDigitYearMax.Value);
                    }

                    return reader => reader.GetUtcTime(expectedTag);
                }

                if (fieldData.TagType == UniversalTagNumber.GeneralizedTime)
                {
                    Debug.Assert(fieldData.DisallowGeneralizedTimeFractions != null);
                    bool disallowFractions = fieldData.DisallowGeneralizedTimeFractions.Value;

                    return reader => reader.GetGeneralizedTime(expectedTag, disallowFractions);
                }

                Debug.Fail($"No DateTimeOffset handler for {fieldData.TagType}");
                throw new CryptographicException();
            }

            if (typeT == typeof(BigInteger))
            {
                return reader => reader.GetInteger(expectedTag);
            }

            if (typeT.IsLayoutSequential)
            {
                if (fieldData.TagType == UniversalTagNumber.Sequence)
                {
                    return reader => DeserializeCustomType(reader, typeT, expectedTag);
                }
            }

            throw new AsnSerializationConstraintException(
                SR.Format(SR.Cryptography_AsnSerializer_UnhandledType, typeT.FullName));
        }

        private static Type GetArrayItemType(Type arrayType)
        {
            if (arrayType.IsArray)
            {
                if (arrayType.GetArrayRank() != 1)
                {
                    throw new AsnSerializationConstraintException(
                        SR.Format(SR.Cryptography_AsnSerializer_NoMultiDimensionalArrays, arrayType.FullName));
                }

                Type baseType = arrayType.GetElementType();

                if (baseType.IsArray)
                {
                    throw new AsnSerializationConstraintException(
                        SR.Format(SR.Cryptography_AsnSerializer_NoJaggedArrays, arrayType.FullName));
                }

                return baseType;
            }
            return arrayType;
        }

        private static object DeserializeCustomType(AsnReader reader, Type typeT, Asn1Tag expectedTag)
        {
            // Blows up if there's no default ctor
            object target = Activator.CreateInstance(typeT);

            AsnReader sequence = reader.ReadSequence(expectedTag);
            if (!expectedTag.IsUniversal)
            {
                // Application or Context specific tags seem to be followed by actual ASN Tags, for example:
                // 0x7e, 0x6a, 0x30, 0x68
                // 
                // 0x7e = 01 1 11110 = [Application 30] Constructed
                // 0x6a = Object Length 106 Bytes
                //   0x30 = 00 1 10000 = [Universal 16] Constructed = Sequence
                //   0x68 = Sequence Length 104 Bytes

                var asnType = typeT.GetCustomAttribute<AsnTypeAttribute>();
                switch (asnType)
                {
                    case null:
                    case SequenceOfAttribute _:
                        sequence = sequence.ReadSequence();
                        break;
                    default:
                        throw new InvalidOperationException("Unhandled tag");
                }
            }

            var fields = typeT.GetFields(FieldFlags);
            var fieldInfos = new Dictionary<(TagClass, int), FieldInfo>();
            foreach (var field in fields)
            {
                GetFieldInfo(field.FieldType, field, null, out var serializerFieldData);
                var etag = serializerFieldData.ExpectedTag;
                fieldInfos[(etag.TagClass, etag.TagValue)] = field;
            }

            // TODO: This now requires [ExpectedTag(int)] on each field.
            // Not sure if that's a bad thing - mixing positional and ExpectedTag fields could be bad
            // I need a FieldInfo to know what to deserialize into, so I need to know which one the
            // "next" field in the sequence is.
            //
            // I think that changing GetOrderedFields would be the way, but then, how to deal with this struct?
            //
            // [ExpectedTag(0)]
            // public string Foo;
            //
            // public int Bar;
            //
            // [ExpectedTag(1)
            // public int Baz;
            //
            // This looks like something that should throw an exception for ambiguity?

            while (sequence.HasData)
            {
                int? contentsLength;
                int bytesRead;
                var tag = sequence.ReadTagAndLength(out contentsLength, out bytesRead);
                if (!tag.IsUniversal)
                {
                    // Need to advance the sequence to skip the tag and go to the next tag. Data looks like:
                    // 0xa0, 0x03, 0x02, 0x01, 0x05
                    // 0xa0 = 10 1 00000 = [ContextSpecific 0] Constructed
                    // 0x03 = Length 3 Bytes
                    //   0x02 = 00 0 00010 = [Universal 2] Primitive = Integer
                    //   0x01 = Integer Length 1 Byte
                    //   0x05 = Integer Value: 5
                    sequence = sequence.AdvanceReader(bytesRead);
                    //tag = sequence.ReadTagAndLength(out contentsLength, out bytesRead);
                    var tc = (tag.TagClass, tag.TagValue);
                    if (fieldInfos.ContainsKey(tc))
                    {
                        var fieldInfo = fieldInfos[tc];

                        Deserializer deserializer = GetDeserializer(fieldInfo.FieldType, fieldInfo, false);
                        try
                        {
                            var val = deserializer(sequence);
                            fieldInfo.SetValue(target, val);
                        }
                        catch (Exception e)
                        {
                            throw new CryptographicException(
                                SR.Format(
                                    SR.Cryptography_AsnSerializer_SetValueException,
                                    fieldInfo.Name,
                                    fieldInfo.DeclaringType.FullName),
                                e);
                        }
                    }
                    else
                    {
                        sequence = sequence.AdvanceReader(contentsLength.Value);
                    }
                }                
            }

            sequence.ThrowIfNotEmpty();
            return target;
        }

        private static Deserializer ExplicitValueDeserializer(Deserializer valueDeserializer, Asn1Tag expectedTag)
        {
            return reader => ExplicitValueDeserializer(reader, valueDeserializer, expectedTag);
        }

        private static object ExplicitValueDeserializer(
            AsnReader reader,
            Deserializer valueDeserializer,
            Asn1Tag expectedTag)
        {
            AsnReader innerReader = reader.ReadSequence(expectedTag);
            object val = valueDeserializer(innerReader);

            innerReader.ThrowIfNotEmpty();
            return val;
        }

        private static Deserializer GetPrimitiveDeserializer(Type typeT, Asn1Tag tag)
        {
            if (typeT == typeof(bool))
                return reader => reader.ReadBoolean(tag);
            if (typeT == typeof(int))
                return TryOrFail((AsnReader reader, out int value) => reader.TryReadInt32(tag, out value));
            if (typeT == typeof(uint))
                return TryOrFail((AsnReader reader, out uint value) => reader.TryReadUInt32(tag, out value));
            if (typeT == typeof(short))
                return TryOrFail((AsnReader reader, out short value) => reader.TryReadInt16(tag, out value));
            if (typeT == typeof(ushort))
                return TryOrFail((AsnReader reader, out ushort value) => reader.TryReadUInt16(tag, out value));
            if (typeT == typeof(byte))
                return TryOrFail((AsnReader reader, out byte value) => reader.TryReadUInt8(tag, out value));
            if (typeT == typeof(sbyte))
                return TryOrFail((AsnReader reader, out sbyte value) => reader.TryReadInt8(tag, out value));
            if (typeT == typeof(long))
                return TryOrFail((AsnReader reader, out long value) => reader.TryReadInt64(tag, out value));
            if (typeT == typeof(ulong))
                return TryOrFail((AsnReader reader, out ulong value) => reader.TryReadUInt64(tag, out value));

            throw new AsnSerializationConstraintException(
                SR.Format(
                    SR.Cryptography_AsnSerializer_UnhandledType,
                    typeT.FullName));
        }

        private static Deserializer DefaultValueDeserializer(
            Deserializer valueDeserializer,
            Deserializer literalValueDeserializer,
            bool isOptional,
            byte[] defaultContents,
            Asn1Tag? expectedTag)
        {
            return reader =>
                DefaultValueDeserializer(
                    reader,
                    expectedTag,
                    valueDeserializer,
                    literalValueDeserializer,
                    defaultContents,
                    isOptional);
        }

        private static object DefaultValueDeserializer(
            AsnReader reader,
            Asn1Tag? expectedTag,
            Deserializer valueDeserializer,
            Deserializer literalValueDeserializer,
            byte[] defaultContents,
            bool isOptional)
        {
            if (reader.HasData)
            {
                Asn1Tag actualTag = reader.PeekTag();

                if (expectedTag == null ||
                    // Normalize the constructed bit so only class and value are compared
                    actualTag.AsPrimitive() == expectedTag.Value.AsPrimitive())
                {
                    return valueDeserializer(reader);
                }
            }

            if (isOptional)
            {
                return null;
            }

            if (defaultContents != null)
            {
                return DefaultValue(defaultContents, literalValueDeserializer);
            }

            throw new CryptographicException(SR.Cryptography_Der_Invalid_Encoding);
        }

        private static object DeserializeChoice(AsnReader reader, Type typeT)
        {
            var lookup = new Dictionary<(TagClass, int), LinkedList<FieldInfo>>();
            LinkedList<FieldInfo> fields = new LinkedList<FieldInfo>();
            PopulateChoiceLookup(lookup, typeT, fields);

            Asn1Tag next = reader.PeekTag();

            if (next == Asn1Tag.Null)
            {
                ChoiceAttribute choiceAttr = GetChoiceAttribute(typeT);

                if (choiceAttr.AllowNull)
                {
                    reader.ReadNull();
                    return null;
                }

                throw new CryptographicException(SR.Cryptography_Der_Invalid_Encoding);
            }

            var key = (next.TagClass, next.TagValue);

            if (lookup.TryGetValue(key, out LinkedList<FieldInfo> fieldInfos))
            {
                LinkedListNode<FieldInfo> currentNode = fieldInfos.Last;
                FieldInfo currentField = currentNode.Value;
                object currentObject = Activator.CreateInstance(currentField.DeclaringType);
                Deserializer deserializer = GetDeserializer(currentField.FieldType, currentField);
                object deserialized = deserializer(reader);
                currentField.SetValue(currentObject, deserialized);

                while (currentNode.Previous != null)
                {
                    currentNode = currentNode.Previous;
                    currentField = currentNode.Value;

                    object nextObject = Activator.CreateInstance(currentField.DeclaringType);
                    currentField.SetValue(nextObject, currentObject);

                    currentObject = nextObject;
                }

                return currentObject;
            }

            throw new CryptographicException(SR.Cryptography_Der_Invalid_Encoding);
        }

        private static void PopulateChoiceLookup(
            Dictionary<(TagClass, int), LinkedList<FieldInfo>> lookup,
            Type typeT,
            LinkedList<FieldInfo> currentSet)
        {
            foreach (FieldInfo fieldInfo in GetOrderedFields(typeT))
            {
                Type fieldType = fieldInfo.FieldType;

                if (!CanBeNull(fieldType))
                {
                    throw new AsnSerializationConstraintException(
                        SR.Format(
                            SR.Cryptography_AsnSerializer_Choice_NonNullableField,
                            fieldInfo.Name,
                            fieldInfo.DeclaringType.FullName));
                }

                fieldType = UnpackIfNullable(fieldType);

                if (currentSet.Contains(fieldInfo))
                {
                    throw new AsnSerializationConstraintException(
                        SR.Format(
                            SR.Cryptography_AsnSerializer_Choice_TypeCycle,
                            fieldInfo.Name,
                            fieldInfo.DeclaringType.FullName));
                }

                LinkedListNode<FieldInfo> newNode = new LinkedListNode<FieldInfo>(fieldInfo);
                currentSet.AddLast(newNode);

                if (GetChoiceAttribute(fieldType) != null)
                {
                    PopulateChoiceLookup(lookup, fieldType, currentSet);
                }
                else
                {
                    GetFieldInfo(
                        fieldType,
                        fieldInfo,
                        null,
                        out SerializerFieldData fieldData);

                    if (fieldData.DefaultContents != null)
                    {
                        // ITU-T-REC-X.680-201508
                        // The application of the DEFAULT keyword is in SEQUENCE (sec 25, "ComponentType" grammar)
                        // There is no such keyword in the grammar for CHOICE.
                        throw new AsnSerializationConstraintException(
                            SR.Format(
                                SR.Cryptography_AsnSerializer_Choice_DefaultValueDisallowed,
                                fieldInfo.Name,
                                fieldInfo.DeclaringType.FullName));
                    }

                    var key = (fieldData.ExpectedTag.TagClass, fieldData.ExpectedTag.TagValue);

                    if (lookup.TryGetValue(key, out LinkedList<FieldInfo> existingSet))
                    {
                        FieldInfo existing = existingSet.Last.Value;

                        throw new AsnSerializationConstraintException(
                            SR.Format(
                                SR.Cryptography_AsnSerializer_Choice_ConflictingTagMapping,
                                fieldData.ExpectedTag.TagClass,
                                fieldData.ExpectedTag.TagValue,
                                fieldInfo.Name,
                                fieldInfo.DeclaringType.FullName,
                                existing.Name,
                                existing.DeclaringType.FullName));
                    }

                    lookup.Add(key, new LinkedList<FieldInfo>(currentSet));
                }

                currentSet.RemoveLast();
            }
        }

        private static FieldInfo[] GetOrderedFields(Type typeT)
        {
            return s_orderedFields.GetOrAdd(
                typeT,
                t =>
                {
                    // https://github.com/dotnet/corefx/issues/14606 asserts that ordering by the metadata
                    // token on a SequentialLayout will produce the fields in their layout order.
                    //
                    // Some other alternatives:
                    // * Add an attribute for controlling the field read order.
                    //    fieldInfos.Select(fi => (fi, fi.GetCustomAttribute<AsnFieldOrderAttribute>(false)).
                    //      Where(val => val.Item2 != null).OrderBy(val => val.Item2.OrderWeight).Select(val => val.Item1);
                    //
                    // * Use Marshal.OffsetOf as a sort key
                    //
                    // * Some sort of interface to return the fields in a declared order, using either
                    //   an existing object, or Activator.CreateInstance.  It would need to check that
                    //   any returned fields actually were declared on the type that was queried.
                    //
                    // * Invent more alternatives
                    FieldInfo[] fieldInfos = t.GetFields(FieldFlags);

                    if (fieldInfos.Length == 0)
                    {
                        return Array.Empty<FieldInfo>();
                    }

                    try
                    {
                        int token = fieldInfos[0].MetadataToken;
                    }
                    catch (InvalidOperationException)
                    {
                        // If MetadataToken isn't available (like in ILC) then just hope that
                        // the fields are returned in declared order.  For the most part that
                        // will result in data misaligning to fields and deserialization failing,
                        // thus a CryptographicException.
                        return fieldInfos;
                    }

                    Array.Sort(fieldInfos, (x, y) => x.MetadataToken.CompareTo(y.MetadataToken));
                    return fieldInfos;
                });
        }

        private static void GetFieldInfo(
            Type typeT,
            FieldInfo fieldInfo,
            AsnTypeAttribute overrideAsnTypeAttribute,
            out SerializerFieldData serializerFieldData)
        {
            serializerFieldData = new SerializerFieldData();

            object[] typeAttrs = fieldInfo?.GetCustomAttributes(typeof(AsnTypeAttribute), false);
            if (typeAttrs == null || typeAttrs.Length == 0)
            {
                if (overrideAsnTypeAttribute != null)
                {
                    typeAttrs = new object[] { overrideAsnTypeAttribute };
                }
                else
                {
                    typeAttrs = Array.Empty<object>();
                }
            }

            if (typeAttrs.Length > 1)
            {
                throw new AsnSerializationConstraintException(
                    SR.Format(
                        fieldInfo.Name,
                        fieldInfo.DeclaringType.FullName,
                        typeof(AsnTypeAttribute).FullName));
            }

            ExpectedTagAttribute tagOverride;
            if (fieldInfo == null)
            {
                tagOverride = typeT?.GetCustomAttribute<ExpectedTagAttribute>(false);
            }
            else
            {
                tagOverride = fieldInfo.GetCustomAttribute<ExpectedTagAttribute>(false);
            }

            Type unpackedType = UnpackIfNullable(typeT);

            if (typeAttrs.Length == 1)
            {
                var attr = typeAttrs[0] as AsnTypeAttribute;
                Type[] expectedTypes = attr.ExpectedTypes;
                serializerFieldData.AsnType = attr;
                serializerFieldData.WasCustomized = true;

                
                

                if (attr is AnyValueAttribute)
                {
                    serializerFieldData.IsAny = true;
                    if (expectedTypes == null)
                    {
                        expectedTypes = new[] { typeof(ReadOnlyMemory<byte>) };
                    }
                }
                else if (attr is IntegerAttribute)
                {
                    if (expectedTypes == null)
                    {
                        expectedTypes = new[] {
                            typeof(ReadOnlyMemory<byte>),
                            typeof(BigInteger),
                            typeof(byte), typeof(sbyte),
                            typeof(ushort), typeof(short),
                            typeof(uint), typeof(int),
                            typeof(ulong), typeof(long)
                        };
                    }
                    serializerFieldData.TagType = UniversalTagNumber.Integer;
                }
                else if (attr is BitStringAttribute)
                {
                    if (expectedTypes == null)
                    {
                        expectedTypes = new[] { typeof(ReadOnlyMemory<byte>) };
                    }
                    serializerFieldData.TagType = UniversalTagNumber.BitString;
                }
                else if (attr is OctetStringAttribute)
                {
                    if (expectedTypes == null)
                    {
                        expectedTypes = new[] { typeof(ReadOnlyMemory<byte>) };
                    }
                    serializerFieldData.TagType = UniversalTagNumber.OctetString;
                }
                else if (attr is ObjectIdentifierAttribute oid)
                {
                    serializerFieldData.PopulateOidFriendlyName = oid.PopulateFriendlyName;
                    if (expectedTypes == null)
                    {
                        expectedTypes = new[] { typeof(Oid), typeof(string) };
                    }
                    serializerFieldData.TagType = UniversalTagNumber.ObjectIdentifier;

                    if (oid.PopulateFriendlyName && unpackedType == typeof(string))
                    {
                        throw new AsnSerializationConstraintException(
                            SR.Format(
                                SR.Cryptography_AsnSerializer_PopulateFriendlyNameOnString,
                                fieldInfo.Name,
                                fieldInfo.DeclaringType.FullName,
                                typeof(Oid).FullName));
                    }
                }
                else if (attr is BMPStringAttribute)
                {
                    if (expectedTypes == null)
                    {
                        expectedTypes = new[] { typeof(string) };
                    }
                    serializerFieldData.TagType = UniversalTagNumber.BMPString;
                }
                else if (attr is IA5StringAttribute)
                {
                    if (expectedTypes == null)
                    {
                        expectedTypes = new[] { typeof(string) };
                    }
                    serializerFieldData.TagType = UniversalTagNumber.IA5String;
                }
                else if (attr is UTF8StringAttribute)
                {
                    if (expectedTypes == null)
                    {
                        expectedTypes = new[] { typeof(string) };
                    }
                    serializerFieldData.TagType = UniversalTagNumber.UTF8String;
                }
                else if (attr is PrintableStringAttribute)
                {
                    if (expectedTypes == null)
                    {
                        expectedTypes = new[] { typeof(string) };
                    }
                    serializerFieldData.TagType = UniversalTagNumber.PrintableString;
                }
                else if (attr is VisibleStringAttribute)
                {
                    if (expectedTypes == null)
                    {
                        expectedTypes = new[] { typeof(string) };
                    }
                    serializerFieldData.TagType = UniversalTagNumber.VisibleString;
                }
                else if (attr is SequenceOfAttribute)
                {
                    serializerFieldData.IsCollection = true;
                    if (expectedTypes == null)
                    {
                        expectedTypes = new Type[] { GetArrayItemType(fieldInfo.FieldType) };
                    }
                    serializerFieldData.TagType = UniversalTagNumber.SequenceOf;
                }
                else if (attr is SetOfAttribute)
                {
                    serializerFieldData.IsCollection = true;
                    //expectedTypes = null;
                    serializerFieldData.TagType = UniversalTagNumber.SetOf;
                }
                else if (attr is UtcTimeAttribute utcAttr)
                {
                    if (expectedTypes == null)
                    {
                        expectedTypes = new[] { typeof(DateTimeOffset) };
                    }
                    serializerFieldData.TagType = UniversalTagNumber.UtcTime;

                    if (utcAttr.TwoDigitYearMax != 0)
                    {
                        serializerFieldData.TwoDigitYearMax = utcAttr.TwoDigitYearMax;

                        if (serializerFieldData.TwoDigitYearMax < 99)
                        {
                            throw new AsnSerializationConstraintException(
                                SR.Format(
                                    SR.Cryptography_AsnSerializer_UtcTimeTwoDigitYearMaxTooSmall,
                                    fieldInfo.Name,
                                    fieldInfo.DeclaringType.FullName,
                                    serializerFieldData.TwoDigitYearMax));
                        }
                    }
                }
                else if (attr is GeneralizedTimeAttribute genTimeAttr)
                {
                    if (expectedTypes == null)
                    {
                        expectedTypes = new[] { typeof(DateTimeOffset) };
                    }
                    serializerFieldData.TagType = UniversalTagNumber.GeneralizedTime;
                    serializerFieldData.DisallowGeneralizedTimeFractions = genTimeAttr.DisallowFractions;
                }
                else if (attr is GeneralStringAttribute genStrAttr) // Must come after more specific string attributes!
                {
                    if (expectedTypes == null)
                    {
                        expectedTypes = new[] { typeof(string) };
                    }
                    serializerFieldData.TagType = UniversalTagNumber.GeneralString;
                }
                else
                {
                    Debug.Fail($"Unregistered {nameof(AsnTypeAttribute)} kind: {attr.GetType().FullName}");
                    throw new CryptographicException();
                }

                Debug.Assert(serializerFieldData.IsCollection || expectedTypes != null);

                if (serializerFieldData.IsNotCollection
                    && (unpackedType.IsEnum ? Array.IndexOf(expectedTypes, Enum.GetUnderlyingType(unpackedType)) : Array.IndexOf(expectedTypes, unpackedType)) < 0)
                {

                    throw new AsnSerializationConstraintException(
                        SR.Format(
                            SR.Cryptography_AsnSerializer_UnexpectedTypeForAttribute,
                            fieldInfo.Name,
                            fieldInfo.DeclaringType.Namespace,
                            unpackedType.FullName,
                            string.Join(", ", expectedTypes.Select(t => t.FullName))));
                }
            }

            var defaultValueAttr = fieldInfo?.GetCustomAttribute<DefaultValueAttribute>(false);
            serializerFieldData.DefaultContents = defaultValueAttr?.EncodedBytes;

            if (serializerFieldData.TagType == null && !serializerFieldData.IsAny)
            {
                if (unpackedType == typeof(bool))
                {
                    serializerFieldData.TagType = UniversalTagNumber.Boolean;
                }
                else if (unpackedType == typeof(sbyte) ||
                         unpackedType == typeof(byte) ||
                         unpackedType == typeof(short) ||
                         unpackedType == typeof(ushort) ||
                         unpackedType == typeof(int) ||
                         unpackedType == typeof(uint) ||
                         unpackedType == typeof(long) ||
                         unpackedType == typeof(ulong) ||
                         unpackedType == typeof(BigInteger))
                {
                    serializerFieldData.TagType = UniversalTagNumber.Integer;
                }
                else if (unpackedType.IsLayoutSequential)
                {
                    serializerFieldData.TagType = UniversalTagNumber.Sequence;
                }
                else if (unpackedType == typeof(ReadOnlyMemory<byte>) ||
                    unpackedType == typeof(string) ||
                    unpackedType == typeof(DateTimeOffset))
                {
                    throw new AsnAmbiguousFieldTypeException(fieldInfo, unpackedType);
                }
                else if (unpackedType == typeof(Oid))
                {
                    serializerFieldData.TagType = UniversalTagNumber.ObjectIdentifier;
                }
                else if (unpackedType.IsArray)
                {
                    serializerFieldData.TagType = UniversalTagNumber.SequenceOf;
                }
                else if (unpackedType.IsEnum)
                {
                    if (typeT.GetCustomAttributes(typeof(FlagsAttribute), false).Length > 0)
                    {
                        serializerFieldData.TagType = UniversalTagNumber.BitString;
                    }
                    else
                    {
                        serializerFieldData.TagType = UniversalTagNumber.Enumerated;
                    }
                }
                else if (fieldInfo != null)
                {
                    Debug.Fail($"No tag type bound for {fieldInfo.DeclaringType.FullName}.{fieldInfo.Name}");
                    throw new AsnSerializationConstraintException();
                }
            }

            serializerFieldData.IsOptional = fieldInfo?.GetCustomAttribute<OptionalValueAttribute>(false) != null;

            if (serializerFieldData.IsOptional && !CanBeNull(typeT))
            {
                throw new AsnSerializationConstraintException(
                    SR.Format(
                        SR.Cryptography_AsnSerializer_Optional_NonNullableField,
                        fieldInfo.Name,
                        fieldInfo.DeclaringType.FullName));
            }

            bool isChoice = GetChoiceAttribute(typeT) != null;

            if (tagOverride != null)
            {
                if (isChoice && !tagOverride.ExplicitTag)
                {
                    throw new AsnSerializationConstraintException(
                        SR.Format(
                            SR.Cryptography_AsnSerializer_SpecificTagChoice,
                            fieldInfo.Name,
                            fieldInfo.DeclaringType.FullName,
                            typeT.FullName));
                }

                // This will throw for unmapped TagClass values
                serializerFieldData.ExpectedTag = new Asn1Tag(tagOverride.TagClass, tagOverride.TagValue);
                serializerFieldData.HasExplicitTag = tagOverride.ExplicitTag;
                serializerFieldData.SpecifiedTag = true;
                return;
            }

            if (isChoice)
            {
                serializerFieldData.TagType = null;
            }

            serializerFieldData.SpecifiedTag = false;
            serializerFieldData.HasExplicitTag = false;
            serializerFieldData.ExpectedTag = new Asn1Tag(serializerFieldData.TagType.GetValueOrDefault());
        }

        private static object DefaultValue(
            byte[] defaultContents,
            Deserializer valueDeserializer)
        {
            Debug.Assert(defaultContents != null);

            try
            {
                AsnReader defaultValueReader = new AsnReader(defaultContents, AsnEncodingRules.DER);

                object obj = valueDeserializer(defaultValueReader);

                if (defaultValueReader.HasData)
                {
                    throw new AsnSerializerInvalidDefaultException();
                }

                return obj;
            }
            catch (AsnSerializerInvalidDefaultException)
            {
                throw;
            }
            catch (CryptographicException e)
            {
                throw new AsnSerializerInvalidDefaultException(e);
            }
        }

        private static ChoiceAttribute GetChoiceAttribute(Type typeT)
        {
            ChoiceAttribute attr = typeT.GetCustomAttribute<ChoiceAttribute>(inherit: false);

            if (attr == null)
            {
                return null;
            }

            if (attr.AllowNull)
            {
                if (!CanBeNull(typeT))
                {
                    throw new AsnSerializationConstraintException(
                        SR.Format(SR.Cryptography_AsnSerializer_Choice_AllowNullNonNullable, typeT.FullName));
                }
            }

            return attr;
        }

        private static Type UnpackIfNullable(Type typeT)
            => Nullable.GetUnderlyingType(typeT) ?? typeT;

        private static bool CanBeNull(Type t)
            => !t.IsValueType
            || (t.IsGenericType && t.GetGenericTypeDefinition() == typeof(Nullable<>));

        private static Deserializer TryOrFail<T>(TryDeserializer<T> tryDeserializer)
        {
            return reader =>
            {
                if (tryDeserializer(reader, out T value))
                    return value;

                throw new CryptographicException(SR.Cryptography_Der_Invalid_Encoding);
            };
        }

        private struct SerializerFieldData
        {
            internal bool WasCustomized;
            internal UniversalTagNumber? TagType;
            internal bool? PopulateOidFriendlyName;
            internal bool IsAny;
            internal bool IsCollection;
            internal byte[] DefaultContents;
            internal bool HasExplicitTag;
            internal bool SpecifiedTag;
            internal bool IsOptional;
            internal int? TwoDigitYearMax;
            internal Asn1Tag ExpectedTag;
            internal bool? DisallowGeneralizedTimeFractions;
            internal AsnTypeAttribute AsnType;
            internal bool IsNotCollection => !IsCollection;
        }
    }
}
