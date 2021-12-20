﻿using Solnet.Programs.Governance.Enums;
using Solnet.Programs.Utilities;
using Solnet.Wallet;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Solnet.Programs.Governance.Models
{
    /// <summary>
    /// Governance Realm Account
    /// Account PDA seeds" ['governance', name]
    /// </summary>
    public class Realm : GovernanceProgramAccount
    {
        /// <summary>
        /// The layout of the <see cref="Governance"/> structure.
        /// </summary>
        public static class ExtraLayout
        {
            /// <summary>
            /// 
            /// </summary>
            public const int CommunityMintOffset = 1;

            /// <summary>
            /// 
            /// </summary>
            public const int ConfigOffset = 33;

            /// <summary>
            /// 
            /// </summary>
            public const int AuthorityOffset = 99;

            /// <summary>
            /// 
            /// </summary>
            public const int NameOffset = 132;
        }

        /// <summary>
        /// Community mint
        /// </summary>
        public PublicKey CommunityMint;

        /// <summary>
        /// Configuration of the Realm
        /// </summary>
        public RealmConfig Config;

        /// <summary>
        /// Realm authority. The authority must sign transactions which update the realm config
        /// The authority can be transferer to Realm Governance and hence make the Realm self governed through proposals
        /// </summary>
        public PublicKey Authority;

        /// <summary>
        /// Governance Realm name
        /// </summary>
        public string Name;

        /// <summary>
        /// 
        /// </summary>
        /// <param name="data"></param>
        /// <returns></returns>
        public static Realm Deserialize(byte[] data)
        {
            ReadOnlySpan<byte> span = data.AsSpan();

            RealmConfig config = RealmConfig.Deserialize(span.GetSpan(ExtraLayout.ConfigOffset, RealmConfig.Layout.Length));
            PublicKey authority = null;
            bool authorityExists;
            string realmName;

            // council mint public key exists in realm config structure
            if (config.CouncilMint != null)
            {
                int nameOffset = ExtraLayout.NameOffset;
                authorityExists = span.GetBool(ExtraLayout.AuthorityOffset);
                if (authorityExists)
                {
                    authority = span.GetPubKey(ExtraLayout.AuthorityOffset + 1);
                }
                else
                {
                    nameOffset -= PublicKey.PublicKeyLength;
                }

                _ = span.GetString(nameOffset, out realmName);
            }
            else
            {
                // council mint public key does not exist in realm config structure so offsets differ from static values
                int nameOffset = ExtraLayout.NameOffset;
                authorityExists = span.GetBool(ExtraLayout.AuthorityOffset - (PublicKey.PublicKeyLength));
                if (authorityExists)
                {
                    authority = span.GetPubKey(ExtraLayout.AuthorityOffset + 1 - (PublicKey.PublicKeyLength));
                    nameOffset -= PublicKey.PublicKeyLength;
                }
                else
                {
                    nameOffset -= (2 * PublicKey.PublicKeyLength);
                }

                _ = span.GetString(nameOffset, out realmName);
            }

            return new Realm
            {
                AccountType = (GovernanceAccountType)Enum.Parse(typeof(GovernanceAccountType), span.GetU8(Layout.AccountTypeOffset).ToString()), 
                CommunityMint = span.GetPubKey(ExtraLayout.CommunityMintOffset),
                Config = config,
                Authority = authorityExists ? authority : null,
                Name = realmName
            };
        }
    }
}
