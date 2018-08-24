using System;

namespace ASN1Serialize
{
    /// <summary>
    /// Microseconds    ::= INTEGER (0..999999)
    ///                     -- microseconds
    /// </summary>
    public struct Microseconds : IEquatable<Microseconds>
    {
        private int _value;

        public int Value
        {
            get => _value;
            set
            {
                if (!IsValidValue(value))
                {
                    throw new ArgumentOutOfRangeException(nameof(value), "Value must range from 0 to 999999, but was " + value);
                }
                _value = value;
            }
        }

        public Microseconds(int value)
        {
            if (!IsValidValue(value))
            {
                throw new ArgumentOutOfRangeException(nameof(value), "Value must range from 0 to 999999, but was " + value);
            }
            _value = value;
        }

        public static bool IsValidValue(int value)
            => value >= 0 && value <= 999999;

        public override string ToString() => Value + "μs";

        public override bool Equals(object obj)
            => obj is Microseconds && Equals((Microseconds)obj);

        public bool Equals(Microseconds other)
            => Value == other.Value;

        public override int GetHashCode()
            => -1937169414 + Value.GetHashCode();

        public static bool operator ==(Microseconds microseconds1, Microseconds microseconds2)
            => microseconds1.Equals(microseconds2);

        public static bool operator !=(Microseconds microseconds1, Microseconds microseconds2)
            => !(microseconds1 == microseconds2);

        public static implicit operator Microseconds(int val) => new Microseconds(val);

        public static implicit operator int(Microseconds microsecs) => microsecs.Value;
    }
}
