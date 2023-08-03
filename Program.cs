using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace UXORBreaker
{
	class Program
	{
		static void OutputUsage(string title)
		{
			Console.Write(
$@"{title}

Windows Explorer Drag-n-Drop Usage:
  Simply drop an XOR'd encrypted Unity file into {AppDomain.CurrentDomain.FriendlyName} to create a new decrypted Unity file.

Command Line Usage:
  {AppDomain.CurrentDomain.FriendlyName} [-s] <source> [-d <destination>]

  -s source               Path of encrypted Unity file to load.
  -d destination          Path of decrypted Unity file to save.
                            Default = {{source}}.decrypted

Press any key to exit . . ."
			);

			Console.ReadKey();
		}

		struct Block
		{
			public uint UncompressedSize;
			public uint CompressedSize;
			public ushort Flags;
		}

		struct DirectoryInfo
		{
			public ulong Offset;
			public ulong Size;
			public uint Flags;
			public string Path;
		}

		static void Main(string[] args)
		{
			if (args.Length == 0)
			{
				OutputUsage("Tool to decrypt XOR'd Unity files by Lamp");
				return;
			}
			string sArg = null;
			string dArg = null;
			for (int i = 0, nexti = 1; i < args.Length; i = nexti, nexti++)
			{
				var arg = args[i];
				if (arg.Equals("-s") && args.Length > nexti)
				{
					sArg = args[nexti++];
				}
				else if (arg.Equals("-d") && args.Length > nexti)
				{
					dArg = args[nexti++];
				}
				else
				{
					if (!string.IsNullOrEmpty(sArg))
					{
						OutputUsage("Multiple source files are not supported!");
						return;
					}
					sArg = args[i];
				}
			}

			if (string.IsNullOrEmpty(sArg))
			{
				OutputUsage("Source path not specified!");
				return;
			}

			if (!File.Exists(sArg))
			{
				OutputUsage($"Source file '{Path.GetFullPath(sArg)}' does not exist!");
				return;
			}

			if (string.IsNullOrEmpty(dArg))
			{
				dArg = Path.GetFullPath(sArg) + ".decrypted";
			}

			if (File.Exists(dArg) || Directory.Exists(dArg))
			{
				OutputUsage($"Destination '{Path.GetFullPath(dArg)}' already exist!");
				return;
			}

#if !DEBUG
			try
#endif
			{
				using (Stream file = File.OpenRead(sArg))
				{
					using (FileReader reader = new FileReader(file, EndianType.BigEndian))
					{
						if (!reader.TryReadStringNullTerm(out string type) || type != "UnityFS") // Type
						{
							throw new NotSupportedException("File is not UnityFS");
						}
						if (!reader.TryReadInt32(out int _) ||                                   // Version
							!reader.TryReadStringNullTerm(out string _) ||                       // UnityWebBundleVersion
							!reader.TryReadStringNullTerm(out string _))                         // UnityWebMinimumRevision
						{
							throw new InvalidDataException("Cannot read file header");
						}
						long bundleSizePtr = file.Position;
						if (!reader.TryReadUInt64(out ulong bundleSize) ||                       // BundleSize **** Need to update too after stripping PGR header (-= 0x46)
							!reader.TryReadInt32(out int metadataSize) ||                        // MetadataSize
							metadataSize == 0 ||
							!reader.TryReadInt32(out int uncompressedMetadataSize) ||            // UncompressedMetadataSize
							uncompressedMetadataSize < 24 ||
							!reader.TryReadInt32(out int flags))                                 // Flags **** Need to update too after stripping PGR header (&= 0xFFFFFDFF)
						{
							throw new InvalidDataException("Cannot read file header");
						}
						if ((flags & 0x200) != 0)
						{
							reader.ReadBytes(0x46);
						}
						Console.WriteLine("Reading metadata...");
						if ((flags & 0x00000080) != 0)
						{
							long metaposition = (long)bundleSize - metadataSize;
							if (metaposition < 0 || metaposition > file.Length)
							{
								throw new DataMisalignedException("Metadata offset is out of bounds");
							}
							throw new NotImplementedException($"Unsupported metadata position");
							file.Position = metaposition;
						}
						//if ((flags & 0x0000003e) != 2)
						//{
						//	throw new NotImplementedException($"Compresstion type '0x{flags & 0x0000003f:X2}' is not supported");
						//}

						List<Block> blocks = new List<Block>();
						List<DirectoryInfo> directories = new List<DirectoryInfo>();

						byte[] metadataBlob = new byte[uncompressedMetadataSize];

						using (MemoryStream uncompressedMetadata = new MemoryStream(new byte[uncompressedMetadataSize]))
						{
							using (Lz4DecodeStream decodeStream = new Lz4DecodeStream(file, metadataSize))
							{
								decodeStream.ReadBuffer(uncompressedMetadata, uncompressedMetadataSize);
								uncompressedMetadata.Position = 0;
								using (FileReader metaReader = new FileReader(uncompressedMetadata, EndianType.BigEndian))
								{
									if (!metaReader.TryReadHash128(out Guid _))
									{
										throw new InvalidDataException("Cannot read file metadata");
									}

									if (!metaReader.TryReadUInt32(out uint blockcount) || blockcount * 10 + 20 > uncompressedMetadataSize)
									{
										throw new InsufficientMemoryException($"Block count of {blockcount} is too large for metadata size");
									}
									string plural = (blockcount == 1) ? "" : "s";
									Console.WriteLine($"{blockcount} block{plural} found:");
									for (int i = 0; i < blockcount; i++)
									{
										metaReader.TryReadUInt32(out uint uncompressedsize);
										metaReader.TryReadUInt32(out uint compressedsize);
										metaReader.TryReadUInt16(out ushort blockflags);
										Console.WriteLine($"  {i}: ({uncompressedsize}) {compressedsize} 0x{blockflags:X4}");
										blocks.Add(new Block { UncompressedSize = uncompressedsize, CompressedSize = compressedsize, Flags = blockflags });
									}

									if (!metaReader.TryReadUInt32(out uint directorycount) || directorycount * 10 + blockcount * 10 + 20 > uncompressedMetadataSize)
									{
										throw new InsufficientMemoryException($"Directory count of {directorycount} is too large for metadata size");
									}
									plural = (directorycount == 1) ? "y" : "ies";
									Console.WriteLine($"{directorycount} director{plural} found:");
									for (int i = 0; i < directorycount; i++)
									{
										metaReader.TryReadUInt64(out ulong offset);
										metaReader.TryReadUInt64(out ulong size);
										metaReader.TryReadUInt32(out uint directoryflags);
#warning TODO: Limit string parsing to remaining array size
										metaReader.TryReadStringNullTerm(out string path);
										Console.WriteLine($"  {i}: @{offset:X} {size} {directoryflags} \"{path}\"");
										directories.Add(new DirectoryInfo { Offset = offset, Size = size, Flags = directoryflags, Path = path });
									}
									uncompressedMetadata.Position = 0;
									uncompressedMetadata.Read(metadataBlob, 0, uncompressedMetadataSize);
								}
							}
						}

						using (FileStream writer = File.OpenWrite(dArg))
						{
							long blockPtr = file.Position;
							file.Position = 0;

							// Try to guess XOR seed by counting the most common byte in header (likely to be the null bytes)
							int checksize = 256;
							Dictionary<byte, byte> count = new Dictionary<byte, byte>(checksize);
							for (int i = 0; i < checksize; i++)
							{

								var thisbyte = reader.ReadByte();
								if (count.ContainsKey(thisbyte))
								{
									count[thisbyte]++;
								}
								else
								{
									count.Add(thisbyte, 1);
								}
							}
							byte mostCommonByte = 0;
							byte highestCount = 0;
							foreach (KeyValuePair<byte, byte> pair in count)
							{
								if (pair.Value > highestCount)
								{
									mostCommonByte = pair.Key;
									highestCount = pair.Value;
								}
							}
							file.Position = 0;

							// Write header
							for (int i = 0; i < (int)blockPtr - metadataSize; i++)
							{
								writer.WriteByte(reader.ReadByte());
							}

							// Write metadata (uncompressed copy)
							writer.Write(metadataBlob, 0, uncompressedMetadataSize);
							file.Position += metadataSize;

							// Patch bundles size
							writer.Position = bundleSizePtr;
							bundleSize += (ulong)(uncompressedMetadataSize - metadataSize);
							blockPtr += (uncompressedMetadataSize - metadataSize);
							writer.WriteByte((byte)(bundleSize >> 56));
							writer.WriteByte((byte)(bundleSize >> 48));
							writer.WriteByte((byte)(bundleSize >> 40));
							writer.WriteByte((byte)(bundleSize >> 32));
							writer.WriteByte((byte)(bundleSize >> 24));
							writer.WriteByte((byte)(bundleSize >> 16));
							writer.WriteByte((byte)(bundleSize >> 8));
							writer.WriteByte((byte)(bundleSize));
							// Patch metadata size
							metadataSize = uncompressedMetadataSize;
							writer.WriteByte((byte)(metadataSize >> 24));
							writer.WriteByte((byte)(metadataSize >> 16));
							writer.WriteByte((byte)(metadataSize >> 8));
							writer.WriteByte((byte)(metadataSize));
							// Remove compression flag
							//writer.Position += 4;
							writer.Position += 7;
							//writer.WriteByte((byte)(flags >> 24));
							//writer.WriteByte((byte)(flags >> 16));
							//writer.WriteByte((byte)(flags >> 8));
							writer.WriteByte((byte)(flags & 0xFFFFFFC0));
							//Patch out encrypted block flag in metadata
							writer.Position += 20;
							for (int i = 0; i < blocks.Count; i++)
							{
								//writer.Position += 8;
								writer.Position += 9;
								//Block block = blocks[i];
								//writer.WriteByte((byte)(block.Flags >> 8));
								//writer.WriteByte((byte)((block.Flags & 0xFFFFFFC0) + 2)); // Remove XOR flag and set compression to LZ4
								writer.WriteByte(3); // Set compression to LZ4hc
							}
							writer.Position = blockPtr;

#warning TODO: Test if blocks share the same seed
							for (int i = 0; i < blocks.Count; i++)
							{
								Block block = blocks[i];
								//if ((block.Flags & 0x0000003e) != 2 && (block.Flags & 0x0000003f) != 0)
								//{
								//	throw new NotImplementedException($"Compresstion type '0x{block.Flags & 0x0000003f:X2}' is not supported");
								//}
								int compressedSize = (int)block.CompressedSize;

								for (int j = 0; j < compressedSize; j++)
								{
									writer.WriteByte((byte)(reader.ReadByte() ^ mostCommonByte));
								}

								Console.WriteLine($"Decrypted block {i} of {blocks.Count}");
							}
						}
					}
				}
			}
#if !DEBUG
			catch (Exception e)
			{
				Console.WriteLine(
$@"An error occurred trying to read {sArg}
{e.StackTrace}

{e.Message}"
);
				Console.ReadKey();
				return;
			}
#endif
		}
	}
}
